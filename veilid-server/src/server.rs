use crate::client_api;
use crate::logs::*;
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
use crate::ptr_lookup::ptr_lookup;
use crate::settings::*;
use crate::tools::*;
use flume::{unbounded, Receiver, Sender};
use futures_util::select;
use futures_util::FutureExt;
use lazy_static::*;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::*;
use veilid_core::tools::*;
use veilid_core::{KeyPairGroup, VeilidAPI};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerMode {
    Normal,
    ShutdownImmediate,
    DumpBootstrapRecords {
        hostname: Option<String>,
        keypairs: KeyPairGroup,
    },
    SignBootstrapPayload {
        lifetime: String,
        cache_ttl_hours: Option<u32>,
        keypairs: KeyPairGroup,
        node_lines: Vec<String>,
    },
}

lazy_static! {
    static ref SHUTDOWN_SWITCH: Mutex<Option<SingleShotEventual<()>>> =
        Mutex::new(Some(SingleShotEventual::new(Some(()))));
}

/// `--panic` causes shutdown() to panic instead of resolving the switch
static PANIC_ON_SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn set_panic_on_shutdown(panic: bool) {
    PANIC_ON_SHUTDOWN.store(panic, Ordering::SeqCst);
}

#[instrument]
pub fn shutdown() {
    if PANIC_ON_SHUTDOWN.load(Ordering::SeqCst) {
        panic!("panic requested");
    }
    if let Some(shutdown_switch) = SHUTDOWN_SWITCH.lock().take() {
        shutdown_switch.resolve(());
    }
}

pub async fn run_veilid_server_subnode(
    subnode: u16,
    settings: Settings,
    server_mode: ServerMode,
    veilid_logs: Logs,
) -> EyreResult<()> {
    let (
        settings_auto_attach,
        settings_client_api_ipc_enabled,
        settings_client_api_network_enabled,
        settings_client_api_ipc_directory,
        settings_client_api_listen_address_addrs,
        subnode_offset,
    ) = {
        let settingsr = settings.read();

        cfg_if! {
            if #[cfg(feature = "virtual-network")] {
                let subnode_offset = if inner.core.network.virtual_network.enabled {
                    // Don't offset ports when using virtual networking
                    0
                } else {
                    subnode
                };
            } else {
                let subnode_offset = subnode;
            }
        }

        (
            settingsr.auto_attach,
            settingsr.client_api.ipc_enabled,
            settingsr.client_api.network_enabled,
            settingsr.client_api.ipc_directory.clone(),
            settingsr
                .client_api
                .listen_address
                .with_offset_port(subnode_offset)?
                .addrs,
            subnode_offset,
        )
    };

    // Create client api state change pipe
    let (sender, receiver): (
        Sender<veilid_core::VeilidUpdate>,
        Receiver<veilid_core::VeilidUpdate>,
    ) = unbounded();

    // Create VeilidCore setup
    let update_callback = Arc::new(move |change: veilid_core::VeilidUpdate| {
        if let Err(e) = sender.send(change) {
            // Don't log here, as that loops the update callback in some cases and will deadlock
            let change = e.into_inner();
            eprintln!("error sending veilid update callback: {:?}", change);
        }
    });
    let core_config = settings
        .get_core_config(subnode, subnode_offset)
        .wrap_err("Mapping to VeilidCore config failed")?;

    // This subnode's log key, computed before core_config is consumed
    #[cfg(feature = "stats")]
    let stats_log_key = veilid_core::VeilidLayerFilter::make_veilid_log_key(
        &core_config.program_name,
        &core_config.namespace,
    );

    // Start Veilid Core and get API
    let veilid_api = veilid_core::api_startup(update_callback, core_config)
        .await
        .inspect_err(|e| {
            eprintln!("VeilidCore startup failed: {:?}", e);
        })
        .wrap_err("VeilidCore startup failed")?;

    // Enable stats logging for this subnode if configured
    #[cfg(feature = "stats")]
    {
        let (enabled, directory, interval_secs) = {
            let settingsr = settings.read();
            (
                settingsr.logging.stats.enabled,
                settingsr.logging.stats.directory.clone(),
                settingsr.logging.stats.interval_secs,
            )
        };
        if enabled {
            let output = if directory.is_empty() {
                veilid_core::StatsOutput::Facility
            } else {
                let dir = std::path::PathBuf::from(&directory);
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    warn!("stats: could not create directory {}: {}", directory, e);
                }
                let filename = if subnode == 0 {
                    "veilid-server.ndjson".to_owned()
                } else {
                    format!("veilid-server-{}.ndjson", subnode)
                };
                veilid_core::StatsOutput::File(dir.join(filename))
            };
            veilid_core::StatsManager::init(
                Some(stats_log_key),
                veilid_core::StatsSettings {
                    enabled: true,
                    interval_secs,
                    output,
                },
            );
            info!("Stats logging enabled every {}s", interval_secs);
        }
    }
    // Start client api if one is requested
    let capi_enabled = settings_client_api_ipc_enabled || settings_client_api_network_enabled;
    let mut capi = if capi_enabled && matches!(server_mode, ServerMode::Normal) {
        let some_capi =
            client_api::ClientApi::new(veilid_api.clone(), veilid_logs.clone(), settings.clone());
        some_capi.clone().run(
            if settings_client_api_ipc_enabled {
                Some(settings_client_api_ipc_directory.join(subnode.to_string()))
            } else {
                None
            },
            if settings_client_api_network_enabled {
                settings_client_api_listen_address_addrs
            } else {
                vec![]
            },
        );
        Some(some_capi)
    } else {
        None
    };

    // Signing needs no network
    let auto_attach = match server_mode {
        ServerMode::Normal => settings_auto_attach,
        ServerMode::SignBootstrapPayload { .. } => false,
        _ => true,
    };

    // Process all updates
    let capi2 = capi.clone();
    let update_receiver_shutdown = SingleShotEventual::new(Some(()));
    let mut update_receiver_shutdown_instance = update_receiver_shutdown.instance().fuse();
    let update_receiver_jh = spawn(
        "update_receiver",
        async move {
            loop {
                select! {
                    res = receiver.recv_async() => {
                        if let Ok(change) = res {
                            if let Some(capi) = &capi2 {
                                // Handle state changes for JSON API
                                capi.clone().handle_update(change);
                            }
                        } else {
                            break;
                        }
                    }
                    _ = update_receiver_shutdown_instance => {
                        break;
                    }
                };
            }
        }
        .in_current_span(),
    );

    // Auto-attach if desired
    let mut out = Ok(());
    if auto_attach {
        info!("Auto-attach to the Veilid network");
        if let Err(e) = veilid_api.attach().await {
            out = Err(eyre!(
                "Auto-attaching to the Veilid network failed: {:?}",
                e
            ));
            shutdown();
        }
    }

    // Run the one-shot modes
    if out.is_ok() {
        match &server_mode {
            ServerMode::Normal => {}
            ServerMode::ShutdownImmediate => shutdown(),
            ServerMode::DumpBootstrapRecords { hostname, keypairs } => {
                out = dump_bootstrap_records(&veilid_api, hostname.as_deref(), keypairs).await;
                shutdown();
            }
            ServerMode::SignBootstrapPayload {
                lifetime,
                cache_ttl_hours,
                keypairs,
                node_lines,
            } => {
                out = sign_bootstrap_payload(
                    &veilid_api,
                    lifetime,
                    *cache_ttl_hours,
                    keypairs,
                    node_lines,
                )
                .await;
                shutdown();
            }
        }
    }

    // Idle while waiting to exit
    let shutdown_switch = {
        let shutdown_switch_locked = SHUTDOWN_SWITCH.lock();
        (*shutdown_switch_locked).as_ref().map(|ss| ss.instance())
    };
    if let Some(shutdown_switch) = shutdown_switch {
        shutdown_switch.await;
    }

    // Stop the client api if we have one
    if let Some(c) = capi.as_mut().cloned() {
        c.stop().await;
    }

    // Shut down Veilid API to release state change sender
    veilid_api.shutdown().await;

    // Shut down update receiver now that there are no more updates
    update_receiver_shutdown.resolve(()).await;

    // Wait for update receiver to exit
    let _ = update_receiver_jh.await;

    out
}

/// Print this node's bootstrap record lines, naming it for the legacy lines by the hostname
/// the operator gave or by reverse DNS
async fn dump_bootstrap_records(
    veilid_api: &VeilidAPI,
    operator_hostname: Option<&str>,
    keypairs: &KeyPairGroup,
) -> EyreResult<()> {
    let addresses = wait_for_bootstrap_addresses(veilid_api).await?;
    let mut command = vec!["bootstraprecords".to_owned()];
    // Only the legacy lines name this host
    #[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
    {
        let mut ptr_names = Vec::new();
        for address in &addresses {
            match ptr_lookup(*address).await {
                Ok(name) => ptr_names.push(name),
                Err(e) => eprintln!("No reverse DNS name for {}: {}", address, e),
            }
        }
        let (hostname, warning) =
            choose_legacy_hostname(&addresses, &ptr_names, operator_hostname)?;
        if let Some(warning) = warning {
            eprintln!("Warning: {}", warning);
        }
        command.push("--hostname".to_owned());
        command.push(hostname);
    }
    #[cfg(not(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1")))]
    let _ = (addresses, operator_hostname);
    if !keypairs.is_empty() {
        command.push(keypairs.to_string());
    }
    let records = veilid_api
        .debug(shell_words::join(&command))
        .await
        .map_err(|e| eyre!("Getting bootstrap records failed: {:?}", e))?;
    print!("{}", records);
    Ok(())
}

/// Sign node lines into one payload line, printed on its own
async fn sign_bootstrap_payload(
    veilid_api: &VeilidAPI,
    lifetime: &str,
    cache_ttl_hours: Option<u32>,
    keypairs: &KeyPairGroup,
    node_lines: &[String],
) -> EyreResult<()> {
    let mut command = vec!["bootstrappayload".to_owned(), lifetime.to_owned()];
    if let Some(hours) = cache_ttl_hours {
        command.push("--ttl".to_owned());
        command.push(hours.to_string());
    }
    if !keypairs.is_empty() {
        command.push("--keypairs".to_owned());
        command.push(keypairs.to_string());
    }
    command.extend(node_lines.iter().cloned());
    let payload = veilid_api
        .debug(shell_words::join(&command))
        .await
        .map_err(|e| eyre!("Signing the bootstrap payload failed: {:?}", e))?;
    // The command reports a bad node line as text rather than an error
    if !payload.starts_with("2|") {
        bail!("{}", payload.trim());
    }
    print!("{}", payload);
    Ok(())
}

/// This node's PublicInternet addresses once the network is up, within a one-shot CLI budget
#[expect(
    clippy::disallowed_methods,
    reason = "bounds a one-shot CLI wait, not a node timestamp"
)]
async fn wait_for_bootstrap_addresses(veilid_api: &VeilidAPI) -> EyreResult<Vec<IpAddr>> {
    let start_time = Instant::now();
    let mut addresses = Vec::new();
    while Instant::now().duration_since(start_time) < Duration::from_secs(10) {
        let state = veilid_api
            .get_state()
            .await
            .map_err(|e| eyre!("Getting state failed: {:?}", e))?;
        if state.network.started {
            addresses = bootstrap_addresses(veilid_api).await?;
            if !addresses.is_empty() {
                break;
            }
        }
        sleep(100).await;
    }
    if addresses.is_empty() {
        bail!("This node has no PublicInternet addresses to make bootstrap records from");
    }
    Ok(addresses)
}

async fn bootstrap_addresses(veilid_api: &VeilidAPI) -> EyreResult<Vec<IpAddr>> {
    let listing = veilid_api
        .debug("bootstrapaddresses".to_owned())
        .await
        .map_err(|e| eyre!("Getting bootstrap addresses failed: {:?}", e))?;
    listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            IpAddr::from_str(line).wrap_err_with(|| format!("bad bootstrap address: {}", line))
        })
        .collect()
}

/// The hostname for the legacy record lines: the operator's choice (warned about when it is not
/// an address of this node or a PTR name), else the one agreed PTR name, else the lone address
#[cfg(any(feature = "enable-bootstrap-v0", feature = "enable-bootstrap-v1"))]
pub(crate) fn choose_legacy_hostname(
    addresses: &[IpAddr],
    ptr_names: &[String],
    operator_hostname: Option<&str>,
) -> EyreResult<(String, Option<String>)> {
    let mut names: Vec<String> = ptr_names
        .iter()
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
        .collect();
    names.sort_unstable();
    names.dedup();

    if let Some(hostname) = operator_hostname {
        let is_address = IpAddr::from_str(hostname).is_ok_and(|ip| addresses.contains(&ip));
        let is_name = names.contains(&hostname.trim_end_matches('.').to_ascii_lowercase());
        let warning = (!is_address && !is_name).then(|| {
            format!(
                "{} is neither an address of this node nor a reverse DNS name of one",
                hostname
            )
        });
        return Ok((hostname.to_owned(), warning));
    }
    match (names.as_slice(), addresses) {
        ([name], _) => Ok((name.clone(), None)),
        ([], [address]) => Ok((address.to_string(), None)),
        ([], _) => bail!(
            "No reverse DNS name for this node's {} addresses, pass --bootstrap-hostname",
            addresses.len()
        ),
        (names, _) => bail!(
            "Reverse DNS names disagree ({}), pass --bootstrap-hostname",
            names.join(", ")
        ),
    }
}

//#[instrument(err, skip_all)]
pub async fn run_veilid_server(
    settings: Settings,
    server_mode: ServerMode,
    veilid_logs: Logs,
) -> EyreResult<()> {
    // Now that logging is initialized, surface any unrecognized or deprecated config keys
    settings.warn_unknown_config_keys();
    settings.warn_deprecated_config();
    info!(
        "Storage settings: {}",
        settings.read().core.storage.describe_limits()
    );

    let (subnode_index, subnode_count) = {
        let settingsr = settings.read();
        (
            settingsr.testing.subnode_index,
            settingsr.testing.subnode_count,
        )
    };

    // Ensure we only try to spawn multiple subnodes in 'normal' execution mode
    if !matches!(server_mode, ServerMode::Normal) && subnode_count != 1 {
        bail!("can only have multiple subnodes in 'normal' execution mode");
    }

    // Run all subnodes
    let mut all_subnodes_jh = vec![];
    for subnode in subnode_index..=(subnode_index + subnode_count - 1) {
        debug!("Spawning subnode {}", subnode);
        let jh = spawn(
            &format!("subnode{}", subnode),
            run_veilid_server_subnode(
                subnode,
                settings.clone(),
                server_mode.clone(),
                veilid_logs.clone(),
            ),
        );
        all_subnodes_jh.push(jh);
    }

    // Wait for all subnodes to complete
    for (sn, jh) in all_subnodes_jh.into_iter().enumerate() {
        jh.await?;
        debug!("Subnode {} exited", (sn as u16) + subnode_index);
    }

    // Finally, drop logs
    // this is explicit to ensure we don't accidentally drop them too soon via a move
    drop(veilid_logs);

    Ok(())
}

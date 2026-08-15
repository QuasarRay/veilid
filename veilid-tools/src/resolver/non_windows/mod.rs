use super::*;

use futures_util::future::{select, Either};

cfg_if! {
    if #[cfg(feature="rt-async-std")] {
        mod async_std_providers;
        use async_std_providers::{*, AsyncStdResolver as AsyncResolver};

        use hickory_resolver::{config, system_conf::read_system_conf};

        fn resolver(
            config: config::ResolverConfig,
            options: config::ResolverOpts,
        ) -> AsyncResolver {
            AsyncResolver::builder_with_config(config, AsyncStdConnectionProvider::default()).with_options(options).build()
        }

    } else if #[cfg(feature="rt-tokio")] {
        use hickory_resolver::{config, name_server::TokioConnectionProvider, TokioResolver as AsyncResolver, system_conf::read_system_conf};

        fn resolver(
            config: config::ResolverConfig,
            options: config::ResolverOpts,
        ) -> AsyncResolver {
            AsyncResolver::builder_with_config(config, TokioConnectionProvider::default()).with_options(options).build()
        }
    } else {
        compile_error!("needs executor implementation");
    }
}

/// Head start for the system resolver so a responsive split-horizon view wins the race
const SYSTEM_RESOLVER_HEAD_START_MS: u32 = 500;

struct Resolvers {
    system: Option<Arc<AsyncResolver>>,
    default: Arc<AsyncResolver>,
}

static RESOLVERS: LazyLock<AsyncMutex<Option<Arc<Resolvers>>>> =
    LazyLock::new(|| AsyncMutex::new(None));

async fn with_resolvers<R, F: FnOnce(Arc<Resolvers>) -> PinBoxFutureStatic<R>>(closure: F) -> R {
    let mut resolvers_lock = RESOLVERS.lock().await;
    if let Some(r) = &*resolvers_lock {
        return closure(r.clone()).await;
    }

    let (config, mut options) = (
        config::ResolverConfig::default(),
        config::ResolverOpts::default(),
    );
    options.try_tcp_on_error = true;
    let default = Arc::new(resolver(config, options));

    let system = if let Ok((config, mut options)) = read_system_conf() {
        // UDP-hostile networks need the TCP fallback on the system resolver most of all
        options.try_tcp_on_error = true;
        // The race with the default resolver provides the retry redundancy
        options.attempts = 1;
        Some(Arc::new(resolver(config, options)))
    } else {
        None
    };
    let resolvers = Arc::new(Resolvers { system, default });
    *resolvers_lock = Some(resolvers.clone());
    closure(resolvers).await
}

/// Race the system resolver against the default resolver, first success wins.
/// The system resolver gets a head start, and either side failing waits out the
/// other, so a wedged system resolver costs the head start plus the default
/// resolver's latency instead of its own full retry ladder.
async fn race_lookups<T, E1, E2, SF, DF>(
    opt_system_fut: Option<SF>,
    default_fut: DF,
    what: &str,
) -> Result<T, ResolverError>
where
    E1: fmt::Display,
    E2: fmt::Display,
    SF: Future<Output = Result<T, E1>>,
    DF: Future<Output = Result<T, E2>>,
{
    let default_err =
        |e: E2| ResolverError::Generic(format!("default resolver {} error: {}", what, e));

    let Some(system_fut) = opt_system_fut else {
        return default_fut.await.map_err(default_err);
    };

    let delayed_default_fut = Box::pin(async move {
        sleep(SYSTEM_RESOLVER_HEAD_START_MS).await;
        default_fut.await
    });

    match select(Box::pin(system_fut), delayed_default_fut).await {
        Either::Left((Ok(v), _)) => Ok(v),
        Either::Left((Err(e), default_rest)) => {
            debug!("system resolver {} error: {}", what, e);
            default_rest.await.map_err(default_err)
        }
        Either::Right((Ok(v), _)) => Ok(v),
        Either::Right((Err(e), system_rest)) => {
            debug!("default resolver {} error: {}", what, e);
            system_rest.await.map_err(|e| {
                ResolverError::Generic(format!("system resolver {} error: {}", what, e))
            })
        }
    }
}

/// Cross-platform DNS resolver. This backend uses hickory-resolver, racing the
/// system configuration (with a head start) against a default resolver.
pub struct Resolver {}

impl Resolver {
    /// Resolve the TXT records for `host`, returning each record's text.
    ///
    /// Blocks on a DNS query; the first call also builds and caches the process-wide resolvers.
    ///
    /// Errors with [`ResolverError::Generic`] when every resolver's lookup fails (no such name, network/DNS failure).
    pub async fn txt_lookup<S: AsRef<str>>(host: S) -> Result<Vec<String>, ResolverError> {
        let host = host.as_ref().to_string();
        let txt_result = with_resolvers(|resolvers| {
            Box::pin(async move {
                let system_fut = resolvers.system.clone().map(|r| {
                    let host = host.clone();
                    async move { r.txt_lookup(&host).await }
                });
                let default_resolver = resolvers.default.clone();
                let default_fut = async move { default_resolver.txt_lookup(&host).await };
                race_lookups(system_fut, default_fut, "txt_lookup").await
            })
        })
        .await?;

        let mut out = Vec::new();
        for x in txt_result.iter() {
            let mut record_out = Vec::<u8>::new();
            for txtd in x.txt_data() {
                record_out.extend_from_slice(txtd);
            }
            if let Ok(s) = String::from_utf8(record_out) {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// Reverse-resolve `ip_addr` to a hostname via its PTR record.
    ///
    /// Blocks on a DNS query; the first call also builds and caches the process-wide resolvers.
    ///
    /// Errors with [`ResolverError::Generic`] when every resolver's lookup fails or returns no records.
    pub async fn ptr_lookup(ip_addr: IpAddr) -> Result<String, ResolverError> {
        let ptr_result = with_resolvers(|resolvers| {
            Box::pin(async move {
                let system_fut = resolvers
                    .system
                    .clone()
                    .map(|r| async move { r.reverse_lookup(ip_addr).await });
                let default_resolver = resolvers.default.clone();
                let default_fut = async move { default_resolver.reverse_lookup(ip_addr).await };
                race_lookups(system_fut, default_fut, "ptr_lookup").await
            })
        })
        .await?;

        if let Some(r) = ptr_result.iter().next() {
            Ok(r.to_string().trim_end_matches('.').to_string())
        } else {
            Err(ResolverError::Generic(
                "PTR lookup returned an empty string".to_string(),
            ))
        }
    }
}

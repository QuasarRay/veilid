use super::*;

use futures_util::future::{select, Either};

#[cfg(target_os = "android")]
pub(crate) mod android_resolv;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) mod apple_resolv;
pub(crate) mod config;
pub(crate) mod dns;

/// Head start for the system resolver so a responsive split-horizon view wins the race
const SYSTEM_RESOLVER_HEAD_START_MS: u32 = 500;

/// The system's own view of DNS, whichever form the platform offers
enum SystemResolver {
    NameServers(Vec<SocketAddr>),
    /// The Android OS resolver, which owns its own retries, TCP and private DNS
    #[cfg(target_os = "android")]
    AndroidOs,
}

impl SystemResolver {
    fn discover() -> Option<Self> {
        #[cfg(target_os = "android")]
        if android_resolv::available() {
            return Some(Self::AndroidOs);
        }
        config::system_name_servers().map(Self::NameServers)
    }

    async fn query(&self, name: &str, qtype: u16) -> Result<dns::Response, dns::DnsError> {
        match self {
            Self::NameServers(servers) => dns::query(servers, name, qtype).await,
            #[cfg(target_os = "android")]
            Self::AndroidOs => android_resolv::query(name, qtype).await,
        }
    }
}

struct Resolvers {
    system: Option<SystemResolver>,
    default: Vec<SocketAddr>,
}

impl Resolvers {
    /// Read the nameserver lists fresh so a network change is picked up by the next lookup
    fn discover() -> Self {
        Self {
            system: SystemResolver::discover(),
            default: config::default_name_servers(),
        }
    }
}

/// Race the system resolver against the default resolver, first success wins.
/// The system resolver gets a head start, and either side failing waits out the
/// other, so a wedged system resolver costs the head start plus the default
/// resolver's latency rather than its own timeout.
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

/// Cross-platform DNS resolver. This backend is a built-in minimal DNS client, racing
/// the system resolver (with a head start) against a public fallback list.
pub struct Resolver {}

impl Resolver {
    /// Resolve the TXT records for `host`, returning each record's text.
    ///
    /// Errors with [`ResolverError::Generic`] when every resolver's lookup fails (no such name, network/DNS failure).
    pub async fn txt_lookup<S: AsRef<str>>(host: S) -> Result<Vec<String>, ResolverError> {
        let host = host.as_ref().to_string();
        let resolvers = Resolvers::discover();
        let system_fut = resolvers.system.map(|system| {
            let host = host.clone();
            async move {
                system
                    .query(&host, dns::TYPE_TXT)
                    .await
                    .map(|r| dns::txt_records(&r))
            }
        });
        let default_servers = resolvers.default;
        let default_fut = async move {
            dns::query(&default_servers, &host, dns::TYPE_TXT)
                .await
                .map(|r| dns::txt_records(&r))
        };
        race_lookups(system_fut, default_fut, "txt_lookup").await
    }

    /// Reverse-resolve `ip_addr` to a hostname via its PTR record.
    ///
    /// Errors with [`ResolverError::Generic`] when every resolver's lookup fails or returns no records.
    pub async fn ptr_lookup(ip_addr: IpAddr) -> Result<String, ResolverError> {
        let name = reverse_name(ip_addr);
        let resolvers = Resolvers::discover();
        let system_fut = resolvers.system.map(|system| {
            let name = name.clone();
            async move {
                system
                    .query(&name, dns::TYPE_PTR)
                    .await
                    .map(|r| dns::ptr_record(&r))
            }
        });
        let default_servers = resolvers.default;
        let default_fut = async move {
            dns::query(&default_servers, &name, dns::TYPE_PTR)
                .await
                .map(|r| dns::ptr_record(&r))
        };
        race_lookups(system_fut, default_fut, "ptr_lookup")
            .await?
            .ok_or_else(|| {
                ResolverError::Generic("PTR lookup returned an empty string".to_string())
            })
    }
}

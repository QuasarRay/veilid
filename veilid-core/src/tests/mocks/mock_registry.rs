use super::*;

use crate::network_manager::*;
use crate::routing_table::*;
use crate::storage_manager::*;

pub(crate) async fn init<S: AsRef<str>>(namespace: S) -> VeilidComponentRegistry {
    init_with_config(namespace, |_| {}).await
}

pub(crate) async fn init_with_config<S: AsRef<str>>(
    namespace: S,
    modify_config: impl FnOnce(&mut VeilidConfig),
) -> VeilidComponentRegistry {
    let (update_callback, mut config) = fixture_veilid_core_with_namespace(namespace);
    modify_config(&mut config);
    let startup_options = VeilidStartupOptions::try_new(config, update_callback).unwrap();
    let registry = VeilidComponentRegistry::new(startup_options);
    registry.enable_mock();
    registry.register(ProtectedStore::new);
    registry.register(TableStore::new);
    registry.register(Crypto::new);
    registry.register(StorageManager::new);
    registry.register_with_context(RoutingTable::new, RoutingTableStartupContext::default());
    registry.register_with_context(NetworkManager::new, NetworkManagerStartupContext::default());

    registry.init().await.expect("should init");
    registry.post_init().await.expect("should post init");

    registry
}

pub(crate) async fn terminate(registry: VeilidComponentRegistry) {
    registry.pre_terminate().await;
    registry.terminate().await;
}

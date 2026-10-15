//! The route spec store content comes back from the table store as it was saved.

use super::*;
use crate::crypto::tests_crypto::*;
use crate::tests::*;

pub async fn test_persisted_route_spec_store_content() {
    info!("--- test_persisted_route_spec_store_content ---");
    let registry = mock_registry::init("a").await;
    let table_store = registry.table_store();

    let id = AllocatedRouteSetId::from(fake_route_id());
    let key = fake_public_key();
    let secret_key = fake_secret_key();
    let hops = vec![fake_node_id(), fake_node_id()];
    let route_set = BTreeMap::from([(
        key.clone(),
        RouteSpecDetail {
            secret_key: secret_key.clone(),
            hops: hops.clone(),
        },
    )]);
    let detail = RouteSetSpecDetail::new(
        route_set,
        DirectionSet::all(),
        Stability::Reliable,
        SequenceOrderingSet::all(),
        true,
    )
    .expect("detail");

    let mut content = RouteSpecStoreContent::new(registry.clone());
    content.add_detail(id.clone(), detail);
    let db = table_store
        .open("RouteSpecStore", 1)
        .await
        .expect("route spec store table");
    content.save(&db).await.expect("save");

    let loaded = RouteSpecStoreContent::load(registry.clone())
        .await
        .expect("load");
    let loaded_detail = loaded.get_detail(&id).expect("detail survives");
    let mut loaded_routes = loaded_detail.iter_route_set();
    let (loaded_key, loaded_route) = loaded_routes.next().expect("one route");
    assert_eq!(loaded_key, &key);
    assert_eq!(loaded_route.secret_key, secret_key);
    assert_eq!(loaded_route.hops, hops);
    assert!(loaded_routes.next().is_none());
    assert_eq!(loaded.get_id_by_key(&key), Some(id));

    mock_registry::terminate(registry).await;
}

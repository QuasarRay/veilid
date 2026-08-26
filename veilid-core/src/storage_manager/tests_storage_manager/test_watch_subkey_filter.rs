use super::*;
use crate::tests::*;
use crate::veilid_api::Target;

/// Whether a change notification carries the VALUE is decided per WATCHER.
///
/// A collection commits its head subkey and an element subkey in one
/// transaction, so a watcher of both sees two changed subkeys and the value is
/// suppressed. Narrowing a watch to the element subkeys alone has to restore
/// it, or a reader cannot learn an appended element from the notification and
/// has to go fetch it.
///
/// Pinned because `InboundWatch::changed_subkeys` carries a doc comment saying
/// it "may include non-watched ranges if they were changed as part of an
/// overlapping transaction", which would defeat exactly this. Every mutator of
/// that field routes through the filter in `update_watched_value`, so the
/// comment reads as stale - this is what says so.
pub async fn test_watch_value_reported_per_watcher_range() {
    let (update_callback, config) = fixture_veilid_core();
    let api = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    let registry = api.core_context().unwrap().registry();
    let storage_manager = registry.storage_manager();
    let crypto = api.crypto().unwrap();

    let ck = CRYPTO_KIND_VLD0;
    let vcrypto = crypto.get(ck).expect("vld0 cryptosystem");
    let owner = vcrypto.generate_keypair();
    let owner_pk = owner.key();
    let avcrypto = vcrypto.as_async();

    // Four subkeys: 0 stands in for a collection head, 1..=3 for its elements
    let schema = DHTSchema::dflt(4).expect("schema");
    let schema_data: Bytes = schema.compile().into();
    let opaque_record_key =
        make_opaque_record_key(&avcrypto, owner_pk.ref_value(), &schema_data).await;

    let sig = Signature::new(ck, BareSignature::new(&[0u8; 64]));
    let descriptor = SignedValueDescriptor::new(owner_pk.clone(), schema_data, sig.clone());

    let store = storage_manager
        .get_local_record_store()
        .expect("local record store");
    let record = Record::<LocalRecordDetail>::new(
        Timestamp::now(),
        Arc::new(descriptor),
        LocalRecordDetail::new(SafetySelection::Unsafe(Sequencing::PreferOrdered)),
    )
    .expect("record");
    store
        .new_record(opaque_record_key.clone(), record)
        .await
        .expect("new_record");

    // Watch the ELEMENT subkeys only, deliberately excluding the head at 0
    // Two watchers over the same record, differing only in range: one narrowed
    // to the elements, one covering the head as well. The contrast between them
    // IS the mechanism under test.
    let watch = |tag: u8, low: u32| {
        let params = InboundWatchParameters {
            subkeys: ValueSubkeyRangeSet::single_range(low, 3),
            expiration: Timestamp::new(Timestamp::now().as_u64() + 3_600_000_000u64),
            count: 100,
            watcher_member_id: MemberId::new(ck, BareMemberId::new(&[tag; 32])),
            target: Target::NodeId(NodeId::new(ck, BareNodeId::new(&[tag; 32]))),
        };
        store.watch_record(opaque_record_key.clone(), params, None)
    };
    for (tag, low) in [(7u8, 1u32), (8u8, 0u32)] {
        let watch_result = watch(tag, low).await.expect("watch_record");
        assert!(
            matches!(watch_result, InboundWatchValueResult::Created { .. }),
            "watch {tag} should have been created, got {watch_result:?}"
        );
    }

    let mk_value = |seq: u32, body: &'static [u8]| {
        let vd = EncryptedValueData::new(
            ValueSeqNum::from(seq),
            Bytes::from_static(body),
            owner_pk.clone(),
            None,
        )
        .expect("value data");
        Arc::new(SignedValueData::new(vd, sig.clone()))
    };

    // One commit touching head + one element, the way a collection write does
    let subkey_values: SubkeyValueList =
        vec![(0, mk_value(1, b"head")), (1, mk_value(1, b"element"))];
    store
        .set_subkeys_single_record(
            &opaque_record_key,
            &subkey_values,
            InboundWatchUpdateMode::UpdateAll,
            CommitActionFlushMode::Immediate,
        )
        .await
        .expect("set_subkeys_single_record");

    let changes = store.take_value_changes().await;
    assert_eq!(
        changes.len(),
        2,
        "two watchers, so two changes: {changes:?}"
    );

    let narrowed = changes
        .iter()
        .find(|c| c.subkeys == ValueSubkeyRangeSet::single(1))
        .expect("the elements-only watcher sees subkey 1 alone, not the head");
    assert!(
        narrowed.value.is_some(),
        "a single reported subkey must carry its value, or a log reader cannot \
         learn an appended element from the notification"
    );

    // The control: same commit, same record, only the range differs
    let wide = changes
        .iter()
        .find(|c| c.subkeys != ValueSubkeyRangeSet::single(1))
        .expect("the head-inclusive watcher should also have a change");
    assert_eq!(
        wide.subkeys,
        ValueSubkeyRangeSet::single_range(0, 1),
        "a watcher covering the head sees both subkeys of the commit"
    );
    assert!(
        wide.value.is_none(),
        "two reported subkeys must suppress the value - if this ever carries \
         one, the narrowing below is unnecessary rather than wrong"
    );

    api.shutdown().await;
}

pub async fn test_all() {
    test_watch_value_reported_per_watcher_range().await;
}

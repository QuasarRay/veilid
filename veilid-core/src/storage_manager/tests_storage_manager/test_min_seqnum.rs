//! Sequence-number assignment on an unattached node, so every set takes the offline branch.
//! That still covers the assignment: `prepare_set_value_data` signs before the online check,
//! and the offline path stores what it signed and queues it for replay.

use super::*;
use crate::tests::*;

async fn set_value(
    rc: &RoutingContext,
    record_key: &RecordKey,
    subkey: ValueSubkey,
    data: &[u8],
    min_seqnum: Option<ValueSeqNum>,
) -> VeilidAPIResult<Option<ValueData>> {
    rc.set_dht_value(
        record_key.clone(),
        subkey,
        data.to_vec(),
        Some(SetDHTValueOptions {
            writer: None,
            allow_offline: None,
            min_seqnum,
        }),
    )
    .await
}

async fn local_seq(
    rc: &RoutingContext,
    record_key: &RecordKey,
    subkey: ValueSubkey,
) -> ValueSeqNum {
    let report = rc
        .inspect_dht_record(
            record_key.clone(),
            Some(ValueSubkeyRangeSet::single(subkey)),
            DHTReportScope::Local,
        )
        .await
        .expect("inspect should succeed");
    report.local_seqs()[0]
}

pub async fn test_min_seqnum() {
    let (update_callback, config) = fixture_veilid_core();
    let api = api_startup(update_callback, config)
        .await
        .expect("startup failed");
    let rc = api.routing_context().unwrap();

    let rec = rc
        .create_dht_record(CRYPTO_KIND_VLD0, DHTSchema::dflt(8).unwrap(), None)
        .await
        .unwrap();
    let key = rec.key().clone();

    // No minimum: the ordinary automatic increment
    set_value(&rc, &key, 0, b"a", None).await.unwrap();
    assert_eq!(local_seq(&rc, &key, 0).await, ValueSeqNum::ZERO);
    set_value(&rc, &key, 0, b"b", None).await.unwrap();
    assert_eq!(local_seq(&rc, &key, 0).await, ValueSeqNum::from(1));

    // A minimum at or below the automatic seq changes nothing
    set_value(&rc, &key, 0, b"c", Some(ValueSeqNum::ZERO))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 0).await, ValueSeqNum::from(2));

    // A minimum above it wins
    set_value(&rc, &key, 1, b"a", Some(ValueSeqNum::from(100)))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 1).await, ValueSeqNum::from(100));

    // Identical data and writer already at the minimum keeps the seq
    set_value(&rc, &key, 1, b"a", Some(ValueSeqNum::from(100)))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 1).await, ValueSeqNum::from(100));

    // Identical data below a raised minimum is still raised
    set_value(&rc, &key, 1, b"a", Some(ValueSeqNum::from(200)))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 1).await, ValueSeqNum::from(200));

    // A minimum the seq already satisfies must not freeze it while increments remain
    set_value(&rc, &key, 1, b"b", Some(ValueSeqNum::from(100)))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 1).await, ValueSeqNum::from(201));

    // A write at the max is deferred like any other offline write, for the replay queue to push
    set_value(&rc, &key, 2, b"a", Some(ValueSeqNum::MAX))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 2).await, ValueSeqNum::MAX);

    // With no minimum there is nothing left to write
    let err = set_value(&rc, &key, 2, b"b", None)
        .await
        .expect_err("a subkey at max has no sequence numbers left");
    assert!(err.to_string().contains("sequence number at max"));

    // A minimum the seq already satisfies reads as a retry, so it reuses the seq:
    // - core does not check that the data matches
    // - a node only accepts the retry if it does
    set_value(&rc, &key, 2, b"b", Some(ValueSeqNum::MAX))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 2).await, ValueSeqNum::MAX);

    // An identical rewrite at max needs no new seq, so it is accepted with no minimum at all
    set_value(&rc, &key, 2, b"b", None).await.unwrap();
    assert_eq!(local_seq(&rc, &key, 2).await, ValueSeqNum::MAX);

    // The retry rule keys on the seq satisfying the minimum, not on the minimum being the max
    set_value(&rc, &key, 3, b"a", Some(ValueSeqNum::MAX))
        .await
        .unwrap();
    set_value(&rc, &key, 3, b"b", Some(ValueSeqNum::from(100)))
        .await
        .unwrap();
    assert_eq!(local_seq(&rc, &key, 3).await, ValueSeqNum::MAX);

    rc.close_dht_record(key.clone()).await.unwrap();
    rc.delete_dht_record(key).await.unwrap();

    api.shutdown().await;
}

pub async fn test_all() {
    test_min_seqnum().await;
}

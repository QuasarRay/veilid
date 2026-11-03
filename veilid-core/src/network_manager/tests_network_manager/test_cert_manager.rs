use super::*;
use crate::network_manager::network::native::certificate_manager::{
    CertificateLoad, CertificateManager, CERT_PAIR_KEY,
};
use crate::network_manager::network::native::webtransport_certificate_profile::*;
use crate::tests::*;
use sha2::{Digest, Sha256};

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

const ONE_DAY_SECS: u32 = 24 * 60 * 60;

pub async fn test_generate_certificate() {
    let now = Timestamp::new(1_700_000_000_000_000u64);
    let validity = TimestampDuration::new_secs(7 * ONE_DAY_SECS);
    let cert =
        CertificateManager::generate_certificate(&webtransport_certificate_profile(validity), now)
            .expect("should generate certificate");

    assert_eq!(cert.not_before, now);
    assert_eq!(cert.not_after, now.later(validity));
    let window = cert.not_after.duration_since(cert.not_before);
    assert!(window < WEBTRANSPORT_CERT_MAX_VALIDITY);
    assert!(cert.is_valid_at(now));
    assert!(!cert.is_valid_at(cert.not_after));

    let mut expected = [0u8; 32];
    expected.copy_from_slice(Sha256::digest(&cert.certificate_der).as_ref());
    assert_eq!(cert.hash, expected);

    assert!(
        contains_subslice(&cert.certificate_der, OID_EC_PUBLIC_KEY),
        "certificate should carry the ecPublicKey OID"
    );
    assert!(
        contains_subslice(&cert.certificate_der, OID_PRIME256V1),
        "certificate should carry the prime256v1 (P-256) curve OID"
    );
    assert!(!cert.private_key_der.is_empty());

    let registry = mock_registry::init("test_cert_manager_clamp").await;
    let mgr = CertificateManager::new(
        registry.clone(),
        webtransport_certificate_profile(TimestampDuration::new_secs(30 * ONE_DAY_SECS)),
    );
    mgr.update(now).expect("should update");
    let current = mgr
        .current_certificate(now)
        .expect("should have a current cert");
    let clamped = current.not_after.duration_since(current.not_before);
    assert!(clamped <= WEBTRANSPORT_CERT_MAX_VALIDITY);
    mock_registry::terminate(registry).await;
}

pub async fn test_rotation_timeline() {
    let registry = mock_registry::init("test_cert_manager_rotation").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let mgr = CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));

    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    mgr.update(t0).expect("update t0");
    let c0 = mgr.current_certificate(t0).expect("present C0 at t0");
    let hashes0 = mgr.current_advertisement().cert_hashes;
    assert_eq!(
        hashes0.len(),
        2,
        "current + future-dated next from the start"
    );
    assert_eq!(hashes0[0], c0.hash);
    let c1_hash = hashes0[1];
    assert_ne!(c1_hash, c0.hash);

    let t_mid = t0.later(TimestampDuration::new_secs(6 * ONE_DAY_SECS));
    mgr.update(t_mid).expect("update mid");
    assert_eq!(
        mgr.current_advertisement().cert_hashes,
        hashes0,
        "current hash set stable before rotation"
    );
    assert_eq!(
        mgr.current_certificate(t_mid).unwrap().hash,
        c0.hash,
        "still serving C0"
    );

    let t_overlap = t0.later(TimestampDuration::new_secs(12 * ONE_DAY_SECS + 6 * 60 * 60));
    mgr.update(t_overlap).expect("update overlap");
    assert_eq!(
        mgr.current_certificate(t_overlap).unwrap().hash,
        c0.hash,
        "serve the older cert through the first half of the overlap"
    );
    assert_eq!(
        mgr.current_advertisement().cert_hashes,
        hashes0,
        "still {{C0, C1}} pre-switch"
    );

    let t_after = t0.later(TimestampDuration::new_secs(
        12 * ONE_DAY_SECS + 18 * 60 * 60,
    ));
    mgr.update(t_after).expect("update after switch");
    let served = mgr
        .current_certificate(t_after)
        .expect("present after switch");
    assert_eq!(
        served.hash, c1_hash,
        "promoted the already-published successor C1"
    );
    assert!(served.is_valid_at(t_after));
    let hashes_after = mgr.current_advertisement().cert_hashes;
    assert_eq!(hashes_after.len(), 2);
    assert_eq!(
        hashes_after[0], c1_hash,
        "C1 is now the current certificate"
    );
    assert_ne!(
        hashes_after[1], c1_hash,
        "and a fresh future-dated C2 was staged"
    );
    assert!(
        !hashes_after.contains(&c0.hash),
        "old C0 rolled out of the current hash set"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_maintain_served_changed_on_promotion() {
    let registry = mock_registry::init("test_cert_manager_maintain").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let mgr = CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));

    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    let o0 = mgr.maintain(t0).await.expect("maintain t0");
    assert!(
        o0.served_certificate_changed,
        "the first certificate is a served-cert change (None -> A)"
    );
    assert!(
        o0.current_hashes_changed,
        "current hash set is {{A, B}} from the start"
    );
    let cert_a = mgr.current_certificate(t0).expect("present cert A");
    let a = cert_a.hash;
    let hashes = mgr.current_advertisement().cert_hashes;
    assert_eq!(hashes.len(), 2, "current + future-dated next");
    let b = hashes[1];
    assert_ne!(b, a);

    let t_mid = t0.later(TimestampDuration::new_secs(6 * ONE_DAY_SECS));
    let o_mid = mgr.maintain(t_mid).await.expect("maintain mid");
    assert!(
        !o_mid.served_certificate_changed,
        "served cert must not change while A is current"
    );
    assert!(
        !o_mid.current_hashes_changed,
        "current hash set unchanged mid-life"
    );
    assert_eq!(mgr.current_certificate(t_mid).unwrap().hash, a);

    let t_overlap = t0.later(TimestampDuration::new_secs(12 * ONE_DAY_SECS + 6 * 60 * 60));
    let o_overlap = mgr.maintain(t_overlap).await.expect("maintain overlap");
    assert!(
        !o_overlap.served_certificate_changed,
        "served cert is still A until the mid-overlap switch"
    );
    assert_eq!(
        mgr.current_certificate(t_overlap).unwrap().hash,
        a,
        "still serving A"
    );

    let t_after = t0.later(TimestampDuration::new_secs(
        12 * ONE_DAY_SECS + 18 * 60 * 60,
    ));
    let o_after = mgr.maintain(t_after).await.expect("maintain after switch");
    assert!(
        o_after.served_certificate_changed,
        "mid-overlap promotion must re-key the endpoint (served cert A -> B)"
    );
    assert!(
        o_after.current_hashes_changed,
        "current hash set rolls to {{B, C}}"
    );
    let served_after = mgr
        .current_certificate(t_after)
        .expect("present cert after promotion")
        .hash;
    assert_eq!(served_after, b, "now serving the promoted successor B");
    assert_ne!(served_after, a, "no longer serving A");

    mock_registry::terminate(registry).await;
}

pub async fn test_persist_reload() {
    let registry = mock_registry::init("test_cert_manager_persist").await;
    let now = Timestamp::new(1_700_000_000_000_000u64);
    let validity = TimestampDuration::new_secs(8 * ONE_DAY_SECS);

    let mgr1 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr1.load_or_generate(now).await.expect("generate+persist");
    let hashes_before = mgr1.current_advertisement().cert_hashes;
    assert_eq!(
        hashes_before.len(),
        2,
        "current + future-dated next both staged and persisted"
    );
    let cert_before = mgr1
        .current_certificate(now)
        .expect("present a cert before reload");

    let mgr2 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let restored = mgr2
        .load_from_storage()
        .await
        .expect("should load from storage");
    assert_eq!(
        restored,
        CertificateLoad::Restored,
        "should have restored persisted certificates"
    );

    assert_eq!(mgr2.current_advertisement().cert_hashes, hashes_before);
    let cert_after = mgr2
        .current_certificate(now)
        .expect("present a cert after reload");
    assert_eq!(cert_after.hash, cert_before.hash);
    assert_eq!(cert_after.certificate_der, cert_before.certificate_der);
    assert_eq!(
        cert_after.private_key_der, cert_before.private_key_der,
        "private key round-trips through the table store"
    );
    assert_eq!(cert_after.not_after, cert_before.not_after);

    mock_registry::terminate(registry).await;
}

type PeerHashSnapshot = (Timestamp, Vec<[u8; 32]>);

pub async fn test_restart_preserves_certs_mid_window() {
    let registry = mock_registry::init("test_cert_manager_restart_midwindow").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    let mgr1 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr1.load_or_generate(t0).await.expect("generate + persist");
    let served_before = mgr1.current_certificate(t0).expect("serve c0 at t0").hash;
    let hashes_before = mgr1.current_advertisement().cert_hashes;
    assert_eq!(hashes_before.len(), 2, "cold start reports current + next");

    let restart_at = t0.later(TimestampDuration::new_secs(60 * 60));
    let mgr2 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr2.load_or_generate(restart_at)
        .await
        .expect("restart: load persisted state");

    let served_after = mgr2
        .current_certificate(restart_at)
        .expect("serve after restart")
        .hash;
    assert_eq!(
        served_after, served_before,
        "restart must serve the identical certificate"
    );
    assert_eq!(
        mgr2.current_advertisement().cert_hashes,
        hashes_before,
        "restart must report the identical hash set (peers' pins stay valid)"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_restart_across_switch_point() {
    let registry = mock_registry::init("test_cert_manager_restart_switch").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    let mgr1 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr1.load_or_generate(t0).await.expect("generate + persist");
    let c0 = mgr1.current_certificate(t0).expect("serve c0 at t0");
    let n0 = mgr1
        .current_certificate(c0.not_after)
        .expect("staged successor covers c0's expiry");
    let hashes_before = mgr1.current_advertisement().cert_hashes;
    assert!(hashes_before.contains(&c0.hash));
    assert!(hashes_before.contains(&n0.hash));

    let switch_us = n0.not_before.as_u64() + (c0.not_after.as_u64() - n0.not_before.as_u64()) / 2;
    let restart_at = Timestamp::new(switch_us + 1);

    let mgr2 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr2.load_or_generate(restart_at)
        .await
        .expect("restart past switch point");

    let served_after = mgr2
        .current_certificate(restart_at)
        .expect("serve after restart")
        .hash;
    assert_eq!(
        served_after, n0.hash,
        "restart past the switch must promote the already-published successor, not mint fresh"
    );
    assert!(
        hashes_before.contains(&served_after),
        "served hash was pinned by peers before the restart"
    );

    let hashes_after = mgr2.current_advertisement().cert_hashes;
    assert_eq!(hashes_after.len(), 2, "current + freshly staged successor");
    assert!(
        hashes_after.contains(&served_after),
        "served cert is one of the current hashes"
    );
    assert!(
        !hashes_after.contains(&c0.hash),
        "c0 has rolled out of the current hash set"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_restart_after_current_expiry() {
    let registry = mock_registry::init("test_cert_manager_restart_curexpiry").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    let mgr1 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr1.load_or_generate(t0).await.expect("generate + persist");
    let c0 = mgr1.current_certificate(t0).expect("serve c0 at t0");
    let n0 = mgr1
        .current_certificate(c0.not_after)
        .expect("staged successor covers c0's expiry");
    let hashes_before = mgr1.current_advertisement().cert_hashes;
    assert!(hashes_before.contains(&n0.hash));

    let restart_at = t0
        .later(validity)
        .later(TimestampDuration::new_secs(60 * 60));
    let mgr2 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr2.load_or_generate(restart_at)
        .await
        .expect("restart after current expiry");

    let served_after = mgr2
        .current_certificate(restart_at)
        .expect("serve after restart")
        .hash;
    assert_eq!(
        served_after, n0.hash,
        "must serve the still-valid, already-published successor"
    );
    assert!(
        hashes_before.contains(&served_after),
        "served hash was pinned by peers before the restart"
    );
    assert_eq!(
        mgr2.current_advertisement().cert_hashes.len(),
        2,
        "current + freshly staged successor"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_restart_after_total_outage() {
    let registry = mock_registry::init("test_cert_manager_restart_outage").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    let mgr1 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr1.load_or_generate(t0).await.expect("generate + persist");
    assert_eq!(mgr1.current_advertisement().cert_hashes.len(), 2);

    let restart_at = t0
        .later(validity)
        .later(validity)
        .later(TimestampDuration::new_secs(ONE_DAY_SECS));
    let mgr2 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr2.load_or_generate(restart_at)
        .await
        .expect("restart after total outage");

    let served_cert = mgr2
        .current_certificate(restart_at)
        .expect("serve a freshly minted cert after recovery");
    assert!(
        served_cert.is_valid_at(restart_at),
        "the freshly minted current cert is valid right now"
    );
    let hashes_after = mgr2.current_advertisement().cert_hashes;
    assert_eq!(
        hashes_after.len(),
        2,
        "recovered a full current + next pair"
    );
    assert!(
        hashes_after.contains(&served_cert.hash),
        "served cert is one of the current hashes"
    );

    let successor_hash = hashes_after
        .iter()
        .copied()
        .find(|&h| h != served_cert.hash)
        .expect("a distinct staged successor");
    let successor = mgr2
        .current_certificate(served_cert.not_after)
        .expect("staged successor covers current's expiry");
    assert_eq!(successor.hash, successor_hash);
    assert!(
        successor.not_before > restart_at,
        "the staged successor is future-dated"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_backwards_clock_does_not_regenerate() {
    let registry = mock_registry::init("test_cert_manager_backwards_clock").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    let mgr1 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr1.load_or_generate(t0).await.expect("generate + persist");
    let hashes_before = mgr1.current_advertisement().cert_hashes;
    assert_eq!(hashes_before.len(), 2);
    let served_before = mgr1.current_certificate(t0).expect("serve c0 at t0").hash;
    assert!(hashes_before.contains(&served_before));

    let backwards = t0.earlier(TimestampDuration::new_secs(2 * ONE_DAY_SECS));
    let mgr2 =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr2.load_or_generate(backwards)
        .await
        .expect("restart with a backwards clock");

    let served_cert_after = mgr2
        .current_certificate(backwards)
        .expect("serving must continue through skew: the unexpired current is still served");
    let served_after = served_cert_after.hash;

    assert!(
        hashes_before.contains(&served_after),
        "backwards clock caused a never-published certificate to be served: the served hash \
         is not in the pre-restart hash set, which would fail every peer's pin check"
    );

    assert_eq!(
        served_after, served_before,
        "backwards-clock restart must keep serving the original persisted current (c0), \
         not regenerate and not promote"
    );

    assert_eq!(
        mgr2.current_advertisement().cert_hashes,
        hashes_before,
        "backwards clock must not change the current hash set"
    );

    let outcome = mgr2
        .maintain(backwards)
        .await
        .expect("maintain at the backwards instant");
    assert!(
        !outcome.served_certificate_changed,
        "backwards-clock maintain must not re-key the endpoint (served cert unchanged)"
    );
    assert!(
        !outcome.current_hashes_changed,
        "backwards-clock maintain must not republish dial info (current hash set unchanged)"
    );
    assert_eq!(
        mgr2.current_certificate(backwards)
            .expect("still serving after maintain")
            .hash,
        served_before,
        "still serving the original c0 after a backwards-clock maintain tick"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_current_hashes_continuity_property() {
    let registry = mock_registry::init("test_cert_manager_continuity").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let mgr = CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    mgr.update(t0).expect("establish the initial rolling pair");

    let c0 = mgr.current_certificate(t0).expect("serve c0 at t0");
    let n0 = mgr
        .current_certificate(c0.not_after)
        .expect("staged successor covers c0's expiry");
    let sliding_window_us = n0.not_before.as_u64() - c0.not_before.as_u64();

    let six_hours = TimestampDuration::new_secs(6 * 60 * 60);
    let freshness_window_us = sliding_window_us - six_hours.as_u64();

    let mut prev_served = c0.hash;
    let mut prev_hashes = mgr.current_advertisement().cert_hashes;
    assert_eq!(prev_hashes.len(), 2);

    let mut snapshots: Vec<PeerHashSnapshot> = Vec::new();
    snapshots.push((t0, prev_hashes.clone()));

    let ticks = 120 * 4;
    let mut now = t0;
    for tick in 1..=ticks {
        now = now.later(six_hours);

        let served_before = mgr
            .current_certificate(now)
            .expect("(a) a certificate is always served")
            .hash;

        let outcome = mgr.maintain(now).await.expect("maintain tick");

        let served_cert = mgr
            .current_certificate(now)
            .expect("(a) a certificate is always served after maintain");
        let served = served_cert.hash;
        assert!(
            served_cert.is_valid_at(now),
            "tick {tick}: served cert valid at now"
        );

        let hashes = mgr.current_advertisement().cert_hashes;

        assert_eq!(
            hashes.len(),
            2,
            "tick {tick}: must report exactly two hashes"
        );
        assert!(
            hashes.contains(&served),
            "tick {tick}: served hash must be in the current hash set"
        );

        if served != prev_served {
            assert!(
                prev_hashes.contains(&served),
                "tick {tick}: served hash rotated to a cert not current last tick"
            );
        }

        assert_eq!(
            outcome.served_certificate_changed,
            served != served_before,
            "tick {tick}: served_certificate_changed must track the actual served hash"
        );

        snapshots.retain(|(t, _)| now.as_u64() - t.as_u64() < freshness_window_us);
        for (snap_t, snap) in &snapshots {
            assert!(
                snap.contains(&served),
                "tick {tick}: served hash absent from a peer snapshot only {}us old \
                 (< freshness window {}us) -> that peer cannot connect",
                now.as_u64() - snap_t.as_u64(),
                freshness_window_us
            );
        }

        if tick % 4 == 0 {
            snapshots.push((now, hashes.clone()));
        }

        prev_served = served;
        prev_hashes = hashes;
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_continuity_property_with_restarts() {
    let registry = mock_registry::init("test_cert_manager_continuity_restarts").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let mut mgr =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    mgr.load_or_generate(t0)
        .await
        .expect("initial generate + persist");

    let c0 = mgr.current_certificate(t0).expect("serve c0 at t0");
    let n0 = mgr
        .current_certificate(c0.not_after)
        .expect("staged successor covers c0's expiry");
    let sliding_window_us = n0.not_before.as_u64() - c0.not_before.as_u64();
    let six_hours = TimestampDuration::new_secs(6 * 60 * 60);
    let freshness_window_us = sliding_window_us - six_hours.as_u64();

    let mut prev_served = c0.hash;
    let mut prev_hashes = mgr.current_advertisement().cert_hashes;
    assert_eq!(prev_hashes.len(), 2);

    let mut snapshots: Vec<PeerHashSnapshot> = Vec::new();
    snapshots.push((t0, prev_hashes.clone()));

    let switch_us = n0.not_before.as_u64() + (c0.not_after.as_u64() - n0.not_before.as_u64()) / 2;
    let ticks_to_first_switch = (switch_us - t0.as_u64()).div_ceil(six_hours.as_u64());
    let ticks_per_switch = sliding_window_us / six_hours.as_u64();
    // Restart on the ticks bracketing a switch point: one inside the handoff overlap before a
    // promotion is due, one just past a promotion.
    let skewed_restart_ticks = [
        ticks_to_first_switch - 1,
        ticks_to_first_switch + 3 * ticks_per_switch + 1,
    ];

    let ticks: u64 = 120 * 4;
    assert!(
        skewed_restart_ticks.iter().all(|t| *t <= ticks),
        "the derived restart ticks {skewed_restart_ticks:?} must fall inside the {ticks}-tick run"
    );

    let mut now = t0;
    for tick in 1..=ticks {
        now = now.later(six_hours);

        if skewed_restart_ticks.contains(&tick) {
            let backwards_skew = TimestampDuration::new_secs(3 * 60 * 60);
            mgr = CertificateManager::new(
                registry.clone(),
                webtransport_certificate_profile(validity),
            );
            mgr.load_or_generate(now.earlier(backwards_skew))
                .await
                .expect("restart with a backwards-skewed clock");
        } else if tick % 12 == 0 {
            mgr = CertificateManager::new(
                registry.clone(),
                webtransport_certificate_profile(validity),
            );
            mgr.load_or_generate(now)
                .await
                .expect("restart: reload persisted state");
        }

        let served_before = mgr
            .current_certificate(now)
            .expect("(a) a certificate is always served")
            .hash;

        let outcome = mgr.maintain(now).await.expect("maintain tick");

        let served_cert = mgr
            .current_certificate(now)
            .expect("(a) a certificate is always served after maintain");
        let served = served_cert.hash;
        assert!(
            served_cert.is_valid_at(now),
            "tick {tick}: served cert valid at now"
        );
        let hashes = mgr.current_advertisement().cert_hashes;

        assert_eq!(hashes.len(), 2, "tick {tick}: exactly two current hashes");
        assert!(
            hashes.contains(&served),
            "tick {tick}: served hash must be current"
        );

        if served != prev_served {
            assert!(
                prev_hashes.contains(&served),
                "tick {tick}: served hash changed to a cert not current last tick"
            );
        }

        assert_eq!(
            outcome.served_certificate_changed,
            served != served_before,
            "tick {tick}: served_certificate_changed must track maintain's own change"
        );

        snapshots.retain(|(t, _)| now.as_u64() - t.as_u64() < freshness_window_us);
        for (snap_t, snap) in &snapshots {
            assert!(
                snap.contains(&served),
                "tick {tick}: served hash absent from a peer snapshot only {}us old \
                 (< freshness window {}us) -> that peer cannot connect",
                now.as_u64() - snap_t.as_u64(),
                freshness_window_us
            );
        }
        if tick % 4 == 0 {
            snapshots.push((now, hashes.clone()));
        }

        prev_served = served;
        prev_hashes = hashes;
    }

    mock_registry::terminate(registry).await;
}

pub async fn test_rotation_boundary_instants() {
    let registry = mock_registry::init("test_cert_manager_boundaries").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let mgr = CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let t0 = Timestamp::new(1_700_000_000_000_000u64);

    mgr.update(t0).expect("establish the initial rolling pair");
    let c0 = mgr.current_certificate(t0).expect("serve c0 at t0");
    let n0 = mgr
        .current_certificate(c0.not_after)
        .expect("staged successor covers c0's expiry");
    let hashes_before = mgr.current_advertisement().cert_hashes;
    assert!(hashes_before.contains(&c0.hash));
    assert!(hashes_before.contains(&n0.hash));

    let switch_us = n0.not_before.as_u64() + (c0.not_after.as_u64() - n0.not_before.as_u64()) / 2;
    let switch_point = Timestamp::new(switch_us);

    let outcome = mgr
        .maintain(switch_point)
        .await
        .expect("maintain at switch");
    assert!(
        outcome.served_certificate_changed,
        "promotion must occur exactly at the switch point"
    );
    let served = mgr
        .current_certificate(switch_point)
        .expect("something is served at the switch point")
        .hash;
    assert_eq!(served, n0.hash, "promoted the already-published successor");
    assert!(
        hashes_before.contains(&served),
        "the newly-served hash was published before the switch (no surprise cert)"
    );
    assert_eq!(
        mgr.current_advertisement().cert_hashes.len(),
        2,
        "still exactly two current hashes"
    );

    assert!(
        c0.is_valid_at(Timestamp::new(c0.not_after.as_u64() - 1)),
        "c0 is valid an instant before its not_after"
    );
    assert!(
        !c0.is_valid_at(c0.not_after),
        "c0 is invalid exactly at its not_after"
    );
    let served_at_c0_expiry = mgr
        .current_certificate(c0.not_after)
        .expect("a valid successor still covers c0.not_after (no gap)");
    assert_ne!(
        served_at_c0_expiry.hash, c0.hash,
        "the expiring certificate must not be presented at its not_after edge"
    );
    assert!(served_at_c0_expiry.is_valid_at(c0.not_after));

    let _ = mgr
        .maintain(c0.not_after)
        .await
        .expect("maintain at c0.not_after must not panic");
    let served_after = mgr
        .current_certificate(c0.not_after)
        .expect("no gap: a valid certificate is served at c0.not_after");
    assert!(served_after.is_valid_at(c0.not_after));
    assert_eq!(mgr.current_advertisement().cert_hashes.len(), 2);

    mock_registry::terminate(registry).await;
}

pub async fn test_validity_clamp_strictly_under_browser_max() {
    assert_eq!(
        WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.as_u64(),
        TimestampDuration::new_secs(14 * ONE_DAY_SECS).as_u64(),
        "WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY is 14 days"
    );
    assert!(
        WEBTRANSPORT_CERT_MAX_VALIDITY.as_u64() < WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.as_u64(),
        "the largest minted validity must be strictly under the browser reject threshold"
    );

    let registry = mock_registry::init("test_cert_manager_validity_clamp").await;
    let now = Timestamp::new(1_700_000_000_000_000u64);

    let mgr = CertificateManager::new(
        registry.clone(),
        webtransport_certificate_profile(WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY),
    );
    mgr.update(now).expect("update");
    let cert = mgr.current_certificate(now).expect("current cert");
    let window_us = cert.not_after.duration_since(cert.not_before).as_u64();
    assert!(
        window_us < WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.as_u64(),
        "served validity ({}us) must be STRICTLY below the browser reject threshold ({}us)",
        window_us,
        WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.as_u64()
    );

    let mgr_over = CertificateManager::new(
        registry.clone(),
        webtransport_certificate_profile(TimestampDuration::new_secs(30 * ONE_DAY_SECS)),
    );
    mgr_over.update(now).expect("update");
    let cert_over = mgr_over.current_certificate(now).expect("current cert");
    let window_over_us = cert_over
        .not_after
        .duration_since(cert_over.not_before)
        .as_u64();
    assert!(
        window_over_us < WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.as_u64(),
        "an over-ceiling request clamps to STRICTLY below the browser reject threshold"
    );

    mock_registry::terminate(registry).await;
}

pub fn test_max_validity_under_browser_reject_threshold() {
    assert!(
        WEBTRANSPORT_CERT_MAX_VALIDITY.as_u64() < WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.as_u64(),
        "WEBTRANSPORT_CERT_MAX_VALIDITY must be strictly under WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY"
    );
}

pub fn test_handoff_overlap_is_a_slice_of_the_validity() {
    assert!(
        WEBTRANSPORT_CERT_HANDOFF_OVERLAP.as_u64() > 0
            && WEBTRANSPORT_CERT_HANDOFF_OVERLAP.as_u64()
                < WEBTRANSPORT_CERT_DEFAULT_VALIDITY.as_u64(),
        "the handoff overlap must be a nonzero slice of the validity, so the sliding window stays strictly under it"
    );
}

pub async fn test_forward_skew_within_backdate_is_valid() {
    let registry = mock_registry::init("test_cert_manager_forward_skew_within").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;

    let mgr = CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let t_fast = Timestamp::new(1_700_000_000_000_000u64);
    mgr.update(t_fast)
        .expect("mint the rolling pair at the fast-clock instant");

    let forward_skew = TimestampDuration::new_secs(30 * 60);
    let t_now = t_fast.earlier(forward_skew);

    let served = mgr
        .current_certificate(t_now)
        .expect("the current slot is served");
    assert!(
        served.not_before <= t_now,
        "backdated not_before ({:?}) must be at or before the corrected real time ({:?})",
        served.not_before,
        t_now
    );
    assert!(
        served.is_valid_at(t_now),
        "a cert minted under a small forward skew is valid at the corrected real time (no blackhole)"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_forward_skew_beyond_backdate_residual() {
    let registry = mock_registry::init("test_cert_manager_forward_skew_residual").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;

    let mgr = CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let t_fast = Timestamp::new(1_700_000_000_000_000u64);
    mgr.update(t_fast)
        .expect("mint the rolling pair at the fast-clock instant");

    let t_now = t_fast.earlier(TimestampDuration::new_secs(2 * ONE_DAY_SECS));

    let served = mgr
        .current_certificate(t_now)
        .expect("RESIDUAL: current is served even though its not_before is still in the future");
    assert!(
        t_now < served.not_before,
        "even with the backdate, a 2-day forward skew leaves not_before in the real future"
    );
    assert!(
        !served.is_valid_at(t_now),
        "the served cert is NOT valid at t_now by its own window: a real client would reject it \
         (documented residual, not a closed fix)"
    );
    assert_eq!(
        served.hash,
        mgr.current_certificate(t_fast)
            .expect("served at mint")
            .hash,
        "the not-yet-valid cert being served is the current slot"
    );

    let mgr_seed =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_seed
        .load_or_generate(t_fast)
        .await
        .expect("seed + persist a rolling pair");
    let c0 = mgr_seed.current_certificate(t_fast).expect("read c0");
    let n0 = mgr_seed
        .current_certificate(c0.not_after)
        .expect("read staged next (n0) at c0.not_after");

    let db = registry
        .table_store()
        .open(WEBTRANSPORT_CERT_TABLE_NAME, 1)
        .await
        .expect("open the cert table");
    let serialized_pair = db
        .load_serialized(0, Bytes::from_static(CERT_PAIR_KEY))
        .await
        .expect("load the persisted pair")
        .expect("a persisted pair exists");
    let mut pair: serde_json::Value = registry
        .table_store()
        .try_deserialize(&serialized_pair)
        .expect("decode the persisted pair");
    pair["current"] = serde_json::Value::Null;
    db.store_serialized(
        0,
        Bytes::from_static(CERT_PAIR_KEY),
        serialize_table_value(&pair),
    )
    .await
    .expect("store the pair with current blanked");

    let mgr_load =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let restored = mgr_load
        .load_from_storage()
        .await
        .expect("reload the (partial) persisted state");
    assert_eq!(
        restored,
        CertificateLoad::Restored,
        "the next slot still restores"
    );

    let before_next = n0
        .not_before
        .earlier(TimestampDuration::new_secs(ONE_DAY_SECS));
    assert!(
        mgr_load.current_certificate(before_next).is_none(),
        "CONTRAST: the future-dated `next` is NOT served before its not_before (full is_valid_at kept)"
    );
    assert!(
        mgr_load.current_certificate(n0.not_before).is_some(),
        "next is served once it becomes valid"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_corrupted_slot_dropped_and_healed() {
    let registry = mock_registry::init("test_cert_manager_corrupt_slot").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let now = Timestamp::new(1_700_000_000_000_000u64);

    let mgr_seed =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_seed
        .load_or_generate(now)
        .await
        .expect("seed + persist");
    let c0 = mgr_seed.current_certificate(now).expect("current c0");
    let old_cert_der = c0.certificate_der.clone();
    let old_key_der = c0.private_key_der.clone();
    let old_hash = c0.hash;

    let mgr_clean =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    let restored_clean = mgr_clean.load_from_storage().await.expect("clean reload");
    assert_eq!(
        restored_clean,
        CertificateLoad::Restored,
        "a consistent pair reloads"
    );
    let clean = mgr_clean.current_certificate(now).expect("clean current");
    assert_eq!(clean.hash, old_hash, "clean reload preserves c0's hash");
    assert_eq!(
        clean.private_key_der, old_key_der,
        "clean reload recovers c0's key"
    );

    let db = registry
        .table_store()
        .open(WEBTRANSPORT_CERT_TABLE_NAME, 1)
        .await
        .expect("open the cert table");
    let serialized_pair = db
        .load_serialized(0, Bytes::from_static(CERT_PAIR_KEY))
        .await
        .expect("load the persisted pair")
        .expect("a persisted pair exists");
    let mut pair: serde_json::Value = registry
        .table_store()
        .try_deserialize(&serialized_pair)
        .expect("decode the persisted pair");
    let byte = pair["current"]["certificate_der"][0]
        .as_u64()
        .expect("a DER byte");
    pair["current"]["certificate_der"][0] = serde_json::json!(byte ^ 0xff);
    db.store_serialized(
        0,
        Bytes::from_static(CERT_PAIR_KEY),
        serialize_table_value(&pair),
    )
    .await
    .expect("store the corrupted pair");

    let mgr_load =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    assert_eq!(
        mgr_load
            .load_from_storage()
            .await
            .expect("reload does not error on the corrupted slot"),
        CertificateLoad::Restored,
        "the intact next slot still restores while the corrupted current is dropped"
    );
    assert!(
        mgr_load.current_certificate(now).is_none(),
        "the corrupted current slot is DROPPED, not served"
    );

    let mgr_heal =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_heal
        .load_or_generate(now)
        .await
        .expect("load_or_generate heals the corrupted state");
    let healed = mgr_heal
        .current_certificate(now)
        .expect("a fresh current is served");
    assert_ne!(
        healed.hash, old_hash,
        "the corrupted slot was dropped and a FRESH current minted (not the old c0 re-served)"
    );
    assert_ne!(
        healed.certificate_der, old_cert_der,
        "served cert DER is the fresh mint, not the corrupted c0 DER"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_inconsistent_windows_dropped_and_healed() {
    let registry = mock_registry::init("test_cert_manager_window_tamper").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let now = Timestamp::new(1_700_000_000_000_000u64);

    let mgr_seed =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_seed
        .load_or_generate(now)
        .await
        .expect("seed + persist");
    let c0 = mgr_seed.current_certificate(now).expect("current c0");

    let db = registry
        .table_store()
        .open(WEBTRANSPORT_CERT_TABLE_NAME, 1)
        .await
        .expect("open the cert table");
    let serialized_pair = db
        .load_serialized(0, Bytes::from_static(CERT_PAIR_KEY))
        .await
        .expect("load the persisted pair")
        .expect("a persisted pair exists");
    let mut pair: serde_json::Value = registry
        .table_store()
        .try_deserialize(&serialized_pair)
        .expect("decode the persisted pair");
    let late = c0.not_after.as_u64() + 1;
    pair["next"]["not_before"] = serde_json::json!(late);
    db.store_serialized(
        0,
        Bytes::from_static(CERT_PAIR_KEY),
        serialize_table_value(&pair),
    )
    .await
    .expect("store the pair with next's window pushed past current's expiry");

    let mgr_heal =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_heal
        .load_or_generate(now)
        .await
        .expect("load_or_generate heals the tampered pair without panicking");
    let current = mgr_heal
        .current_certificate(now)
        .expect("the intact current slot is served");
    assert_eq!(
        current.hash, c0.hash,
        "the intact current survives while the disjoint next is dropped"
    );
    let next = mgr_heal
        .current_certificate(current.not_after)
        .expect("a re-minted next serves after current expires");
    assert!(
        next.not_before <= current.not_after,
        "the healed pair overlaps: the switch window cannot invert"
    );

    let serialized_pair = db
        .load_serialized(0, Bytes::from_static(CERT_PAIR_KEY))
        .await
        .expect("load the healed pair")
        .expect("a persisted pair exists");
    let mut pair: serde_json::Value = registry
        .table_store()
        .try_deserialize(&serialized_pair)
        .expect("decode the persisted pair");
    let nb = pair["current"]["not_before"].clone();
    pair["current"]["not_after"] = nb;
    db.store_serialized(
        0,
        Bytes::from_static(CERT_PAIR_KEY),
        serialize_table_value(&pair),
    )
    .await
    .expect("store the pair with current's window emptied");

    let mgr_load =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    assert_eq!(
        mgr_load
            .load_from_storage()
            .await
            .expect("reload does not error on the empty-window slot"),
        CertificateLoad::Restored,
        "the intact next slot still restores while the empty-window current is dropped"
    );
    assert!(
        mgr_load.current_certificate(now).is_none(),
        "the empty-window current slot is DROPPED, not served"
    );

    mock_registry::terminate(registry).await;
}

pub async fn test_transient_load_error_preserves_pinned_certs() {
    let registry = mock_registry::init("test_cert_manager_transient_load_err").await;
    let validity = WEBTRANSPORT_CERT_DEFAULT_VALIDITY;
    let now = Timestamp::new(1_700_000_000_000_000u64);

    let mgr_seed =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_seed
        .load_or_generate(now)
        .await
        .expect("seed + persist");
    let pinned = mgr_seed.current_advertisement().cert_hashes;
    assert_eq!(pinned.len(), 2, "two peer-pinned hashes persisted");
    let c0_hash = mgr_seed.current_certificate(now).expect("current c0").hash;

    let db = registry
        .table_store()
        .open(WEBTRANSPORT_CERT_TABLE_NAME, 1)
        .await
        .expect("open cert table");
    let good_record = db
        .load(0, Bytes::from_static(CERT_PAIR_KEY))
        .await
        .expect("load the pair record")
        .expect("pair record present after seed");

    let mgr_clean =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    mgr_clean.load_or_generate(now).await.expect("clean reload");
    assert_eq!(
        mgr_clean.current_certificate(now).expect("c0").hash,
        c0_hash,
        "a clean reload keeps the persisted current cert"
    );
    assert_eq!(
        mgr_clean.current_advertisement().cert_hashes,
        pinned,
        "a clean reload keeps the current hash set"
    );

    db.store_serialized(
        0,
        Bytes::from_static(CERT_PAIR_KEY),
        serialize_table_value(&"corrupt-not-a-struct".to_string()),
    )
    .await
    .expect("overwrite the pair record with an undeserializable value");
    assert!(
        mgr_seed.load_from_storage().await.is_err(),
        "a corrupted record makes load_from_storage return Err (a transient read failure)"
    );

    let mgr_victim =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    assert!(
        mgr_victim.load_or_generate(now).await.is_err(),
        "a transient READ error propagates (non-destructive); it is not swallowed as a cold start"
    );

    db.store(0, Bytes::from_static(CERT_PAIR_KEY), good_record)
        .await
        .expect("clear the transient fault (restore the original record)");

    let mgr_after =
        CertificateManager::new(registry.clone(), webtransport_certificate_profile(validity));
    assert_eq!(
        mgr_after
            .load_from_storage()
            .await
            .expect("the record is readable again"),
        CertificateLoad::Restored,
        "the original persisted state is restored and reloads"
    );
    assert_eq!(
        mgr_after.current_certificate(now).expect("cur").hash,
        c0_hash,
        "the peer-pinned current cert survived the transient error untouched"
    );
    assert_eq!(
        mgr_after.current_advertisement().cert_hashes,
        pinned,
        "the peer-pinned hash set survived the transient error untouched"
    );

    mock_registry::terminate(registry).await;
}

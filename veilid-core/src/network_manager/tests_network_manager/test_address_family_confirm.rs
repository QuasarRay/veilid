use super::*;

// Candidate handles are irrelevant to the decision logic, so tests use ()
fn candidates_with(
    configured: AddressTypeSet,
    confirmed: AddressTypeSet,
    candidate_counts: &[(AddressType, usize)],
) -> AddressFamilyConfirmCandidates<()> {
    let mut candidates: BTreeMap<AddressType, Vec<()>> = BTreeMap::new();
    for (at, count) in candidate_counts {
        candidates.insert(*at, vec![(); *count]);
    }
    AddressFamilyConfirmCandidates {
        configured_address_types: configured,
        confirmed_address_types: confirmed,
        candidates,
    }
}

pub fn test_state_classification() {
    info!("--- test_state_classification ---");

    // Nothing configured is its own state, not a failure
    assert_eq!(
        candidates_with(AddressTypeSet::empty(), AddressTypeSet::empty(), &[]).state(),
        AddressFamilyConfirmState::NoConfiguredAddressTypes
    );

    // Everything already proven by live traffic
    assert_eq!(
        candidates_with(AddressTypeSet::all(), AddressTypeSet::all(), &[]).state(),
        AddressFamilyConfirmState::AllConfiguredConfirmed
    );

    // A missing family with too few candidates blocks probing entirely
    assert_eq!(
        candidates_with(
            AddressTypeSet::all(),
            AddressTypeSet::only(AddressType::IPV4),
            &[(AddressType::IPV6, ADDR_FAMILY_MIN_NODES_TO_CONFIRM - 1)],
        )
        .state(),
        AddressFamilyConfirmState::NotEnoughCandidates
    );

    // A missing family with no candidate entry at all is the same
    assert_eq!(
        candidates_with(
            AddressTypeSet::all(),
            AddressTypeSet::only(AddressType::IPV4),
            &[],
        )
        .state(),
        AddressFamilyConfirmState::NotEnoughCandidates
    );

    // Enough candidates for every missing family: ready to probe
    assert_eq!(
        candidates_with(
            AddressTypeSet::all(),
            AddressTypeSet::empty(),
            &[
                (AddressType::IPV4, ADDR_FAMILY_MIN_NODES_TO_CONFIRM),
                (AddressType::IPV6, ADDR_FAMILY_MIN_NODES_TO_CONFIRM),
            ],
        )
        .state(),
        AddressFamilyConfirmState::ConfirmCandidates
    );
}

pub fn test_resolve_confirms_probe_survivors() {
    info!("--- test_resolve_confirms_probe_survivors ---");

    // A supported/condemned mix confirms the survivors
    assert_eq!(
        resolve_probe_dispositions(
            AddressTypeSet::empty(),
            &[
                (AddressType::IPV4, FamilyProbeDisposition::Supported),
                (AddressType::IPV6, FamilyProbeDisposition::Unsupported),
            ],
        ),
        ConfirmationPassOutcome::Confirm(AddressTypeSet::only(AddressType::IPV4))
    );

    // A family proven by real traffic survives even when every probe fails
    assert_eq!(
        resolve_probe_dispositions(
            AddressTypeSet::only(AddressType::IPV4),
            &[(AddressType::IPV6, FamilyProbeDisposition::Unsupported)],
        ),
        ConfirmationPassOutcome::Confirm(AddressTypeSet::only(AddressType::IPV4))
    );

    // Inconclusive is not proof of support
    assert_eq!(
        resolve_probe_dispositions(
            AddressTypeSet::empty(),
            &[
                (AddressType::IPV4, FamilyProbeDisposition::Supported),
                (AddressType::IPV6, FamilyProbeDisposition::Inconclusive),
            ],
        ),
        ConfirmationPassOutcome::Confirm(AddressTypeSet::only(AddressType::IPV4))
    );
}

pub fn test_resolve_cancelled_defers() {
    info!("--- test_resolve_cancelled_defers ---");

    // Shutdown mid-probe must not publish a partial verdict
    assert_eq!(
        resolve_probe_dispositions(
            AddressTypeSet::empty(),
            &[
                (AddressType::IPV4, FamilyProbeDisposition::Supported),
                (AddressType::IPV6, FamilyProbeDisposition::Cancelled),
            ],
        ),
        ConfirmationPassOutcome::Deferred
    );
}

pub fn test_resolve_all_condemned_defers() {
    info!("--- test_resolve_all_condemned_defers ---");

    // Confirming the empty set would latch the node dark until restart:
    // - an empty confirmed set stops all traffic
    // - no traffic means no network-change event to re-arm confirmation
    assert_eq!(
        resolve_probe_dispositions(
            AddressTypeSet::empty(),
            &[
                (AddressType::IPV4, FamilyProbeDisposition::Unsupported),
                (AddressType::IPV6, FamilyProbeDisposition::Unsupported),
            ],
        ),
        ConfirmationPassOutcome::Deferred
    );
}

pub fn test_probe_round_goes_by_what_the_peer_saw() {
    info!("--- test_probe_round_goes_by_what_the_peer_saw ---");

    let seen_from = |address_type| FamilyProbeAnswer::Answered(Some(address_type));

    // A peer that saw us from the family settles it at once
    let mut round = FamilyProbeRound::new(AddressType::IPV6);
    assert_eq!(
        round.record(seen_from(AddressType::IPV6)),
        Some(FamilyProbeDisposition::Supported)
    );

    // An answer over a named url the browser resolved to IPv4 says nothing about IPv6,
    // for or against
    let mut round = FamilyProbeRound::new(AddressType::IPV6);
    for _ in 0..ADDR_FAMILY_FAILURE_THRESHOLD + 1 {
        assert_eq!(round.record(seen_from(AddressType::IPV4)), None);
    }

    // Nor does an answer that rode another node's flow
    assert_eq!(round.record(FamilyProbeAnswer::Answered(None)), None);

    // Unanswered probes condemn the family at the threshold, whatever was answered between
    for _ in 0..ADDR_FAMILY_FAILURE_THRESHOLD - 1 {
        assert_eq!(round.record(FamilyProbeAnswer::Unanswered), None);
    }
    assert_eq!(round.record(seen_from(AddressType::IPV4)), None);
    assert_eq!(
        round.record(FamilyProbeAnswer::Unanswered),
        Some(FamilyProbeDisposition::Unsupported)
    );
}

pub fn test_named_urls_carry_no_family() {
    info!("--- test_named_urls_carry_no_family ---");

    let v4 = SocketAddress::new(Address::IPV4(Ipv4Addr::new(1, 2, 3, 4)), 5150);
    let v6 = SocketAddress::new(
        Address::IPV6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        5150,
    );

    // Dialed at the socket address
    let udp = DialInfo::udp(v4);
    let ws = DialInfo::try_ws(v4, "ws://1.2.3.4:5150/ws".to_owned()).expect("ws");
    assert!(dial_info_names_its_address(&udp));
    assert!(dial_info_names_its_address(&DialInfo::tcp(v6)));
    assert!(dial_info_names_its_address(&ws));

    // Traffic over an address-dialed transport proves its family
    assert!(transport_names_its_address(
        [&udp, &ws],
        TransportType::new(ProtocolType::WS, AddressType::IPV4)
    ));
    // A transport the node does not offer proves nothing
    assert!(!transport_names_its_address(
        [&udp, &ws],
        TransportType::new(ProtocolType::WS, AddressType::IPV6)
    ));

    #[cfg(feature = "enable-protocol-wss")]
    {
        // The same url under both families: the browser picks the one it resolves
        let named = "wss://bootstrap.example.com:5150/ws".to_owned();
        let named_v4 = DialInfo::try_wss(v4, named.clone()).expect("wss");
        let named_v6 = DialInfo::try_wss(v6, named).expect("wss");
        let literal = DialInfo::try_wss(v4, "wss://1.2.3.4:5150/ws".to_owned()).expect("wss");
        assert!(!dial_info_names_its_address(&named_v4));
        assert!(!dial_info_names_its_address(&named_v6));
        assert!(dial_info_names_its_address(&literal));

        // Traffic over the named transport proves neither family
        let dial_infos = [udp, ws, named_v4, named_v6];
        assert!(!transport_names_its_address(
            &dial_infos,
            TransportType::new(ProtocolType::WSS, AddressType::IPV6)
        ));
        assert!(!transport_names_its_address(
            &dial_infos,
            TransportType::new(ProtocolType::WSS, AddressType::IPV4)
        ));
        // Traffic over the address-dialed one beside it still does
        assert!(transport_names_its_address(
            &dial_infos,
            TransportType::new(ProtocolType::WS, AddressType::IPV4)
        ));
    }

    #[cfg(feature = "enable-protocol-webtransport")]
    {
        let literal = DialInfo::try_webtransport_stream(
            v6,
            "https://[2001:db8::1]:5150/wt".to_owned(),
            vec![],
            None,
        )
        .expect("wts");
        let named = DialInfo::try_webtransport_datagram(
            v6,
            "https://bootstrap.example.com:5150/wt".to_owned(),
            vec![],
            None,
        )
        .expect("wtd");
        assert!(dial_info_names_its_address(&literal));
        assert!(!dial_info_names_its_address(&named));
    }
}

pub fn test_all() {
    test_state_classification();
    test_resolve_confirms_probe_survivors();
    test_resolve_cancelled_defers();
    test_resolve_all_condemned_defers();
    test_probe_round_goes_by_what_the_peer_saw();
    test_named_urls_carry_no_family();
}

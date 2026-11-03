use super::*;
use crate::routing_table::tests_routing_table::fix_crypto_info_list;
use crate::tests::*;

#[derive(Debug)]
struct WtTestNode(Vec<DialInfoDetail>);

impl HasDialInfoDetailList for WtTestNode {
    fn dial_info_detail_list(&self) -> &[DialInfoDetail] {
        &self.0
    }
}

fn direct(di: DialInfo) -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: di,
    }
}

pub fn test_contact_method_prefers_udp_tcp_over_webtransport() {
    let addr = SocketAddress::new(Address::IPV4(Ipv4Addr::new(127, 0, 0, 1)), 5150);
    let url = format!("https://{addr}/");
    let udp = direct(DialInfo::udp(addr));
    let tcp = direct(DialInfo::tcp(addr));
    let wts = direct(
        DialInfo::try_webtransport_stream(addr, url.clone(), vec![[7u8; 32]], None).unwrap(),
    );
    let wtd = direct(
        DialInfo::try_webtransport_datagram(addr, url.clone(), vec![[7u8; 32]], None).unwrap(),
    );

    let ordered_sort = DialInfoDetail::get_ordering_sort(SequenceOrdering::Ordered);

    let full = WtTestNode(vec![wts.clone(), wtd.clone(), udp.clone(), tcp.clone()]);
    let selected = full.filtered_dial_info_details(ordered_sort.as_deref(), &|_| true);

    assert_eq!(
        selected.first().unwrap().dial_info.protocol_type(),
        ProtocolType::TCP,
        "ordered selection must prefer TCP over WebTransport even when WT is listed first"
    );
    let position = |pt: ProtocolType| {
        selected
            .iter()
            .position(|d| d.dial_info.protocol_type() == pt)
            .unwrap()
    };
    assert!(
        position(ProtocolType::WTS) > position(ProtocolType::TCP),
        "WTS must rank below TCP"
    );
    assert!(
        position(ProtocolType::WTS) > position(ProtocolType::UDP),
        "WTS must rank below UDP"
    );

    assert!(
        ProtocolType::all_sequence_ordering_set(SequenceOrdering::Ordered)
            .contains(ProtocolType::WTS),
        "WTS is an ordered transport"
    );
    assert!(
        !ProtocolType::all_sequence_ordering_set(SequenceOrdering::Ordered)
            .contains(ProtocolType::WTD),
        "WTD is unordered and must not appear in the ordered set"
    );

    let wt_only = WtTestNode(vec![wts.clone(), wtd.clone()]);
    let ordered_only = |d: &DialInfoDetail| {
        ProtocolType::all_sequence_ordering_set(SequenceOrdering::Ordered)
            .contains(d.dial_info.protocol_type())
    };
    let selected = wt_only.filtered_dial_info_details(ordered_sort.as_deref(), &ordered_only);
    assert_eq!(
        selected.first().unwrap().dial_info.protocol_type(),
        ProtocolType::WTS,
        "WebTransport must be selected when it is the only directly-usable transport"
    );
}

pub async fn test_wire3_hole_punch_webtransport_requires_webtransport_dial_info() {
    let registry = mock_registry::init("wire3").await;
    {
        let routing_table = registry.routing_table();

        let udp_sa = SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)), 5150);
        let udp_di = DialInfo::udp(udp_sa);
        let wts_di = DialInfo::try_webtransport_stream(
            udp_sa,
            "https://18.218.0.160:5150/".to_string(),
            vec![[0u8; 32]],
            None,
        )
        .expect("should build a valid WTS dial info");
        let wtd_di = DialInfo::try_webtransport_datagram(
            udp_sa,
            "https://18.218.0.160:5150/".to_string(),
            vec![[0u8; 32]],
            None,
        )
        .expect("should build a valid WTD dial info");

        assert!(
            hole_punch_is_webtransport(&wts_di),
            "a WTS hole punch dial info must select the WebTransport punch"
        );
        assert!(
            hole_punch_is_webtransport(&wtd_di),
            "a WTD hole punch dial info must select the WebTransport punch"
        );
        assert!(
            !hole_punch_is_webtransport(&udp_di),
            "a raw UDP hole punch dial info must stay on the raw UDP punch"
        );

        let mk_peer_info = |dids: Vec<DialInfo>| {
            let detail_list: Vec<DialInfoDetail> = dids
                .into_iter()
                .map(|dial_info| DialInfoDetail {
                    class: DialInfoClass::Direct,
                    dial_info,
                })
                .collect();
            let node_info = NodeInfo::new(
                Timestamp::new(0),
                vec![ENVELOPE_VERSION_ENV0],
                fix_crypto_info_list(true),
                PUBLIC_INTERNET_CAPABILITIES.to_vec(),
                ProtocolTypeSet::new(),
                AddressTypeSet::new(),
                detail_list.clone(),
                vec![],
                TransportMtus::default(),
                NodeInfo::min_dial_info_expiration(&detail_list),
            );
            Arc::new(
                PeerInfo::try_new_from_unsigned(
                    &routing_table,
                    RoutingDomain::PublicInternet,
                    node_info,
                )
                .expect("should build unsigned peer info"),
            )
        };

        let receipt = Bytes::from(vec![0u8; RCP0_MIN_RECEIPT_SIZE]);

        let pi_wts = mk_peer_info(vec![wts_di.clone()]);
        let signal_wts = SignalInfo::HolePunch {
            receipt: receipt.clone(),
            peer_info: Arc::new(UnverifiedPeerInfo::from_verified(&pi_wts)),
            opt_dial_info: Some(wts_di),
        };
        assert!(
            signal_wts.validate().is_ok(),
            "a WebTransport dial info present in the peer info must be accepted"
        );

        let signal_none = SignalInfo::HolePunch {
            receipt: receipt.clone(),
            peer_info: Arc::new(UnverifiedPeerInfo::from_verified(&pi_wts)),
            opt_dial_info: None,
        };
        assert!(
            signal_none.validate().is_ok(),
            "a hole punch with no dial info is a raw UDP punch and must be accepted"
        );

        let absent_wts = DialInfo::try_webtransport_stream(
            udp_sa,
            "https://18.218.0.160:5150/".to_string(),
            vec![[7u8; 32]],
            None,
        )
        .expect("should build a valid WTS dial info");
        let pi_only_udp = mk_peer_info(vec![udp_di]);
        let signal_absent = SignalInfo::HolePunch {
            receipt,
            peer_info: Arc::new(UnverifiedPeerInfo::from_verified(&pi_only_udp)),
            opt_dial_info: Some(absent_wts),
        };
        assert!(
            signal_absent.validate().is_err(),
            "a dial info absent from the peer info must be rejected (proves the check runs)"
        );
    }
    mock_registry::terminate(registry).await;
}

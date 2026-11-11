use crate::network_manager::*;
use crate::routing_table::*;
use crate::*;

pub fn fix_typed_node_id(kind: CryptoKind, idx: u8) -> NodeId {
    NodeId::new(
        kind,
        BareNodeId::new(&[
            idx, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]),
    )
}

#[expect(dead_code)]
pub fn fix_typed_node_id_group(valid_kinds: bool, unknown: bool) -> NodeIdGroup {
    let mut tks = NodeIdGroup::new();
    if valid_kinds {
        VALID_CRYPTO_KINDS.iter().for_each(|k| {
            tks.add(fix_typed_node_id(*k, 0));
        });
    }
    if unknown {
        tks.add(fix_typed_node_id(CryptoKind::new([1, 2, 3, 4]), 0));
    }
    tks
}

pub fn fix_crypto_info_list(valid: bool) -> Vec<CryptoInfo> {
    let mut cil: Vec<CryptoInfo> = vec![];
    VALID_CRYPTO_KINDS.into_iter().for_each(|ck| {
        let ci = match ck {
            #[cfg(feature = "enable-crypto-none")]
            CRYPTO_KIND_NONE => CryptoInfo::NONE {
                public_key: BarePublicKey::from_str(if !valid {
                    "xuYisL8R7-qoUQiJtHVpvemzd1x3mH246cMJSkMp6BQ"
                } else {
                    "xMzvYmY1C0B-pUrB9V1pnUf6A1hSqNTOju39UaFxQoU"
                })
                .expect("should parse bare public key"),
            },
            #[cfg(feature = "enable-crypto-vld0")]
            CRYPTO_KIND_VLD0 => CryptoInfo::VLD0 {
                public_key: BarePublicKey::from_str(if !valid {
                    "v6XPfyOoCP_ZP-CWFNrf_pF_dpxsq74p2LW_Q5Q4yPQ"
                } else {
                    "W7ENB-SUWpPA7usY8ORVQf_si5QmFbD1Uqa89Jg2Uc0"
                })
                .expect("should parse bare public key"),
            },
            // #[cfg(feature = "enable-crypto-vld1")]
            // CRYPTO_KIND_VLD1 => CryptoInfo::VLD1 {
            //     encapsulation_key: todo!(),
            //     signing_key: todo!(),
            // },
            _ => {
                unreachable!("missing match arm");
            }
        };
        cil.push(ci);
    });
    cil
}

pub fn fix_crypto_info_list_secrets() -> SecretKeyGroup {
    let mut skg = SecretKeyGroup::new();
    VALID_CRYPTO_KINDS.into_iter().for_each(|ck| {
        let sk = match ck {
            #[cfg(feature = "enable-crypto-none")]
            CRYPTO_KIND_NONE => {
                SecretKey::from_str("NONE:OzMQnZnK9L-BWrU-CqKWYrgF_KetVysxcRICrl6OvXo")
                    .expect("should parse secret key")
            }
            #[cfg(feature = "enable-crypto-vld0")]
            CRYPTO_KIND_VLD0 => {
                SecretKey::from_str("VLD0:hbdjau5sr3rBNwN68XeWLg3rfXnXLaLqfbbqhELqV1E")
                    .expect("should parse secret key")
            }
            // #[cfg(feature = "enable-crypto-vld1")]
            // CRYPTO_KIND_VLD1 => CryptoInfo::VLD1 {
            //     encapsulation_key: todo!(),
            //     signing_key: todo!(),
            // },
            _ => {
                unreachable!("missing match arm");
            }
        };
        skg.add(sk);
    });
    skg
}

pub fn fix_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 160)), 53)
}

pub fn fix_dial_info_detail() -> DialInfoDetail {
    DialInfoDetail {
        class: DialInfoClass::Direct,
        dial_info: DialInfo::TCP(DialInfoTCP {
            socket_address: fix_socket_address(),
        }),
    }
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn fix_relay_socket_address() -> SocketAddress {
    SocketAddress::new(Address::IPV4(Ipv4Addr::new(18, 218, 0, 161)), 53)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn make_public_internet_ready_to_publish(routing_table: &RoutingTable) {
    assert!(
        !routing_table.is_own_direct_dial_info_address(&fix_relay_socket_address()),
        "publishing purges every routing table entry whose direct dial info overlaps our own, \
         so a relay fixture sharing an address with this node would vanish and test nothing"
    );

    let node_info = NodeInfo::new(
        Timestamp::new(0),
        vec![ENVELOPE_VERSION_ENV0],
        fix_crypto_info_list(true),
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::new(),
        AddressTypeSet::new(),
        vec![DialInfoDetail {
            class: DialInfoClass::Direct,
            dial_info: DialInfo::tcp(fix_relay_socket_address()),
        }],
        vec![],
        TransportMtus::default(),
        None,
    );
    let relay_peer_info = Arc::new(
        PeerInfo::try_new_from_node_info(
            routing_table,
            RoutingDomain::PublicInternet,
            &fix_crypto_info_list_secrets(),
            node_info,
        )
        .expect("should build signed relay peer info"),
    );
    let relay_node = routing_table
        .register_node_with_peer_info(
            Arc::new(UnverifiedPeerInfo::from_verified(&relay_peer_info)),
            false,
        )
        .expect("should register relay peer info")
        .unfiltered();

    let controller = routing_table
        .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
    let requirements = controller.read_dyn().relay_requirements();
    let relay = RoutingDomainRelay::new(
        RoutingDomain::PublicInternet,
        relay_node,
        RelayKind::Inbound,
    );

    let mut editor = controller.edit();
    editor.set_network_config(RoutingDomainNetworkConfig::new(
        ProtocolTypeSet::all(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        PUBLIC_INTERNET_CAPABILITIES.iter().copied().collect(),
    ));
    editor.set_relay_compilation(Some(RelayCompilation {
        requirements,
        relays: vec![relay].into(),
    }));
    editor.set_receive_mtus(Some(TransportMtus::default()));
    editor.set_confirmed(true);
    editor.commit();
}

/// PublicInternet as a detection would leave a public server, short of our mtus: direct dial
/// info on every transport, so it needs no relay
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub fn make_public_internet_direct(routing_table: &RoutingTable) {
    let v4 = Ipv4Addr::new(8, 8, 8, 8);
    let v6 = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
    let controller = routing_table
        .get_specific_routing_domain_controller::<PublicInternetRoutingDomainController>();
    let mut editor = controller.edit();
    editor.set_network_config(RoutingDomainNetworkConfig::new(
        ProtocolTypeSet::all(),
        ProtocolTypeSet::all(),
        AddressTypeSet::all(),
        PUBLIC_INTERNET_CAPABILITIES.iter().copied().collect(),
    ));
    editor.set_interface_addresses(vec![
        IfAddr::V4(Ifv4Addr {
            ip: v4,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: None,
        }),
        IfAddr::V6(Ifv6Addr {
            ip: v6,
            netmask: Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0),
            broadcast: None,
        }),
    ]);
    editor.clear_dial_info_details(None, None);
    for ip in [IpAddr::V4(v4), IpAddr::V6(v6)] {
        let socket_addr = SocketAddr::new(ip, 5150);
        let socket_address = SocketAddress::from_socket_addr(socket_addr);
        let mut dial_infos = vec![
            DialInfo::udp_from_socketaddr(socket_addr),
            DialInfo::tcp_from_socketaddr(socket_addr),
            DialInfo::try_ws(socket_address, format!("ws://{socket_addr}/ws")).expect("ws"),
        ];
        #[cfg(feature = "enable-protocol-wss")]
        dial_infos.push(
            DialInfo::try_wss(socket_address, "wss://example.com:5150/ws".to_string())
                .expect("wss"),
        );
        #[cfg(feature = "enable-protocol-webtransport")]
        {
            let url = format!("https://{socket_addr}/wt");
            dial_infos.push(
                DialInfo::try_webtransport_stream(
                    socket_address,
                    url.clone(),
                    vec![[1u8; 32]],
                    None,
                )
                .expect("wts"),
            );
            dial_infos.push(
                DialInfo::try_webtransport_datagram(socket_address, url, vec![[1u8; 32]], None)
                    .expect("wtd"),
            );
        }
        for dial_info in dial_infos.drain(..) {
            editor.add_dial_info_detail(DialInfoDetail {
                class: DialInfoClass::Direct,
                dial_info,
            });
        }
    }
    editor.set_confirmed(true);
    editor.commit();
}

pub fn fix_peer_info(
    routing_table: &RoutingTable,
    crypto_info_list: Vec<CryptoInfo>,
    secret_keys: SecretKeyGroup,
) -> VeilidAPIResult<PeerInfo> {
    fix_peer_info_at(
        routing_table,
        crypto_info_list,
        secret_keys,
        Timestamp::new(0),
    )
}

/// A signed peer info whose node info carries `timestamp`
pub fn fix_peer_info_at(
    routing_table: &RoutingTable,
    crypto_info_list: Vec<CryptoInfo>,
    secret_keys: SecretKeyGroup,
    timestamp: Timestamp,
) -> VeilidAPIResult<PeerInfo> {
    let node_info = NodeInfo::new(
        timestamp,
        vec![ENVELOPE_VERSION_ENV0],
        crypto_info_list,
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::new(),
        AddressTypeSet::new(),
        vec![fix_dial_info_detail()],
        vec![],
        TransportMtus::default(),
        None,
    );

    PeerInfo::try_new_from_node_info(
        routing_table,
        RoutingDomain::PublicInternet,
        &secret_keys,
        node_info,
    )
}

pub fn fix_unsigned_peer_info(
    routing_table: &RoutingTable,
    crypto_info_list: Vec<CryptoInfo>,
) -> VeilidAPIResult<PeerInfo> {
    let node_info = NodeInfo::new(
        Timestamp::new(0),
        vec![ENVELOPE_VERSION_ENV0],
        crypto_info_list,
        PUBLIC_INTERNET_CAPABILITIES.to_vec(),
        ProtocolTypeSet::new(),
        AddressTypeSet::new(),
        vec![fix_dial_info_detail()],
        vec![],
        TransportMtus::default(),
        None,
    );

    PeerInfo::try_new_from_unsigned(routing_table, RoutingDomain::PublicInternet, node_info)
}

/// Crypto info and secret keys of a node no other call returns
pub fn fix_node_keys() -> (Vec<CryptoInfo>, SecretKeyGroup) {
    let mut crypto_info_list: Vec<CryptoInfo> = vec![];
    let mut secret_keys = SecretKeyGroup::new();
    for ck in VALID_CRYPTO_KINDS {
        let (public_key, secret) = Crypto::generate_keypair(ck)
            .expect("should generate keypair")
            .value()
            .into_split();
        let ci = match ck {
            #[cfg(feature = "enable-crypto-none")]
            CRYPTO_KIND_NONE => CryptoInfo::NONE { public_key },
            #[cfg(feature = "enable-crypto-vld0")]
            CRYPTO_KIND_VLD0 => CryptoInfo::VLD0 { public_key },
            _ => {
                unreachable!("missing match arm");
            }
        };
        crypto_info_list.push(ci);
        secret_keys.add(SecretKey::new(ck, secret));
    }
    (crypto_info_list, secret_keys)
}

/// An identity for a mock core to configure, so a reopened core keeps it
pub fn fix_identity() -> (PublicKeyGroup, SecretKeyGroup) {
    let mut public_keys = PublicKeyGroup::new();
    let mut secret_keys = SecretKeyGroup::new();
    for ck in VALID_CRYPTO_KINDS {
        let (public_key, secret_key) = Crypto::generate_keypair(ck)
            .expect("should generate keypair")
            .value()
            .into_split();
        public_keys.add(PublicKey::new(ck, public_key));
        secret_keys.add(SecretKey::new(ck, secret_key));
    }
    (public_keys, secret_keys)
}

/// Configure `identity` as the core's own
pub fn set_identity(
    rt: &mut VeilidConfigRoutingTable,
    identity: &(PublicKeyGroup, SecretKeyGroup),
) {
    rt.public_keys = identity.0.clone();
    rt.secret_keys = identity.1.clone();
}

fn make_distinct_peer_info(routing_table: &RoutingTable) -> PeerInfo {
    let (crypto_info_list, secret_keys) = fix_node_keys();
    fix_peer_info(routing_table, crypto_info_list, secret_keys).expect("should be valid")
}

pub fn seed_nodes(routing_table: &RoutingTable, count: usize) -> Vec<NodeRef> {
    (0..count)
        .map(|_| {
            let pi = make_distinct_peer_info(routing_table);
            routing_table
                .register_node_with_peer_info(
                    Arc::new(UnverifiedPeerInfo::from_verified(&pi)),
                    false,
                )
                .expect("should register")
                .unfiltered()
        })
        .collect()
}

pub fn rank_map(node_refs: &[NodeRef], target: &HashCoordinate) -> HashMap<NodeId, usize> {
    let mut ids: Vec<NodeId> = node_refs
        .iter()
        .map(|nr| nr.node_ids().get(CRYPTO_KIND_VLD0).unwrap_or_log())
        .collect();
    ids.sort_unstable_by(RoutingTable::make_closest_node_id_sort(target.clone()));
    ids.into_iter().enumerate().map(|(n, id)| (id, n)).collect()
}

use crate::*;

cfg_if! {
    if #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))] {
        use network_interfaces::{
            AddressFlags, IfAddr, Ifv4Addr, Ifv6Addr, InterfaceAddress, InterfaceFlags,
            NetworkInterface, NetworkInterfaceAddressState, NetworkInterfaces,
        };

        const STABLE: &str = "2600:1702:7d80:a0f:ac:47d2:bae1:c87";
        const TEMP_OLD: &str = "2600:1702:7d80:a0f:69b6:2e0a:b8d0:936b";
        const TEMP_NEW: &str = "2600:1702:7d80:a0f:9d2c:4736:2e56:424c";
        const LAN: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 58);

        fn running(name: &str) -> NetworkInterface {
            NetworkInterface::new(
                name.to_owned(),
                InterfaceFlags {
                    is_running: true,
                    ..InterfaceFlags::default()
                },
            )
        }

        fn v4(ip: Ipv4Addr) -> InterfaceAddress {
            InterfaceAddress {
                if_addr: IfAddr::V4(Ifv4Addr {
                    ip,
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    broadcast: None,
                }),
                flags: AddressFlags {
                    is_dynamic: true,
                    is_preferred: true,
                    ..AddressFlags::default()
                },
            }
        }

        fn v6(ip: &str, is_temporary: bool, is_preferred: bool) -> InterfaceAddress {
            InterfaceAddress {
                if_addr: IfAddr::V6(Ifv6Addr {
                    ip: ip.parse().unwrap(),
                    netmask: "ffff:ffff:ffff:ffff::".parse().unwrap(),
                    broadcast: None,
                }),
                flags: AddressFlags {
                    is_dynamic: true,
                    is_temporary,
                    is_preferred,
                    ..AddressFlags::default()
                },
            }
        }

        /// One interface as macOS presents it around a privacy-address rotation: a stable
        /// global, a deprecated temporary and a fresh one
        fn wifi() -> BTreeMap<String, NetworkInterface> {
            let mut en0 = running("en0");
            en0.add_address(v4(LAN));
            en0.add_address(v6(STABLE, false, true));
            en0.add_address(v6(TEMP_OLD, true, false));
            en0.add_address(v6(TEMP_NEW, true, true));
            en0.add_address(v6("fe80::58:e37e:2bab:d83f", false, true));
            en0.add_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)));
            BTreeMap::from([("en0".to_owned(), en0)])
        }

        fn state_with_primary_v6(primary: &str) -> NetworkInterfaceAddressState {
            let mut interfaces = wifi();
            NetworkInterfaces::filter_non_primary_global_addresses(
                &mut interfaces,
                Some(LAN),
                Some(primary.parse().unwrap()),
            );
            NetworkInterfaces::interface_address_state_for(&interfaces)
        }

        /// The kernel sends from whichever temporary it prefers; that choice must not move
        /// the published address or read as an interface change
        pub fn test_privacy_address_flip_is_not_a_change() {
            info!("test_privacy_address_flip_is_not_a_change");
            let with_old = state_with_primary_v6(TEMP_OLD);
            let with_new = state_with_primary_v6(TEMP_NEW);
            assert_eq!(with_old, with_new);

            let stable: IpAddr = STABLE.parse().unwrap();
            let published: Vec<IpAddr> = with_new
                .interface_addresses
                .iter()
                .map(|a| a.ip())
                .collect();
            assert!(published.contains(&stable), "stable global published: {published:?}");
            assert!(with_new.own_addresses.contains(&stable));
            for temp in [TEMP_OLD, TEMP_NEW] {
                let temp: IpAddr = temp.parse().unwrap();
                assert!(!published.contains(&temp), "privacy address published: {temp}");
                assert!(with_new.own_addresses.contains(&temp), "privacy address not ours: {temp}");
            }
        }

        /// A global on an interface other than the primary one is unreachable and goes; its
        /// local addresses stay for LocalNetwork, and an interface left empty goes with them
        pub fn test_non_primary_interface_keeps_only_locals() {
            info!("test_non_primary_interface_keeps_only_locals");
            let mut interfaces = wifi();
            let mut cell = running("pdp_ip0");
            cell.add_address(v6("2600:1702:1::5", false, true));
            cell.add_address(v6("fe80::1", false, true));
            interfaces.insert("pdp_ip0".to_owned(), cell);
            let mut lone = running("pdp_ip1");
            lone.add_address(v6("2607:f8b0::9", false, true));
            interfaces.insert("pdp_ip1".to_owned(), lone);

            NetworkInterfaces::filter_non_primary_global_addresses(
                &mut interfaces,
                Some(LAN),
                Some(TEMP_NEW.parse().unwrap()),
            );

            let cell_ips: Vec<IpAddr> = interfaces["pdp_ip0"]
                .addresses()
                .iter()
                .map(|a| a.if_addr().ip())
                .collect();
            assert_eq!(cell_ips, vec!["fe80::1".parse::<IpAddr>().unwrap()]);
            assert!(!interfaces.contains_key("pdp_ip1"));
            assert_eq!(interfaces["en0"].addresses().len(), 5);
        }

        pub async fn test_network_interfaces() {
            info!("testing network interfaces");
            let t1 = get_raw_timestamp();
            let interfaces = NetworkInterfaces::new();
            let count = 100;
            for x in 0..count {
                info!("loop {}", x);
                if let Err(e) = interfaces.refresh().await {
                    error!("error refreshing interfaces: {}", e);
                }
            }
            let t2 = get_raw_timestamp();
            let tdiff = ((t2 - t1) as f64)/1000000.0f64;
            info!("running network interface test with {} iterations took {} seconds", count, tdiff);
            //info!("interfaces: {:#?}", interfaces)
        }
    }
}

pub async fn test_all() {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    {
        test_privacy_address_flip_is_not_a_change();
        test_non_primary_interface_keeps_only_locals();
        test_network_interfaces().await;
    }
}

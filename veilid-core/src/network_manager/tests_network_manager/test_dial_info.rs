use super::*;

/// Verify that a known DialInfo variant round-trips through JSON correctly.
pub async fn test_known_variant_roundtrips() {
    let dial_info = DialInfo::udp(SocketAddress::new(
        Address::IPV4(Ipv4Addr::new(1, 2, 3, 4)),
        5150,
    ));
    let json = serde_json::to_string(&dial_info).expect("should serialize");
    let deserialized: DialInfo = serde_json::from_str(&json).expect("should deserialize");
    assert_eq!(dial_info, deserialized);
}

/// Verify that an unknown `"kind"` tag deserializes to `DialInfo::Unknown`
/// instead of producing a hard error.
pub async fn test_unknown_kind_deserializes() {
    let json = r#"{"kind":"FOO","socket_address":"1.2.3.4:5150","request":"foo://1.2.3.4:5150/"}"#;
    let dial_info: DialInfo = serde_json::from_str(json).expect("should deserialize unknown kind");
    assert!(matches!(dial_info, DialInfo::Unknown));
}

/// Verify that `DialInfo::Unknown` reports `is_valid() == false`.
pub async fn test_unknown_is_not_valid() {
    let json = r#"{"kind":"BAR","socket_address":"10.0.0.1:443"}"#;
    let dial_info: DialInfo = serde_json::from_str(json).expect("should deserialize");
    assert!(matches!(dial_info, DialInfo::Unknown));
    assert!(!dial_info.is_valid());
}

/// Verify that `DialInfo::Unknown` does not match any filter.
pub async fn test_unknown_does_not_match_filter() {
    let json = r#"{"kind":"BAZ","socket_address":"10.0.0.1:443"}"#;
    let dial_info: DialInfo = serde_json::from_str(json).expect("should deserialize");
    assert!(matches!(dial_info, DialInfo::Unknown));

    let filter = DialInfoFilter {
        protocol_type_set: ProtocolTypeSet::all(),
        address_type_set: AddressTypeSet::all(),
    };
    assert!(!dial_info.matches_filter(&filter));
}

/// Verify that a `DialInfoDetail` with an unknown inner DialInfo deserializes successfully.
pub async fn test_detail_with_unknown_deserializes() {
    let json = r#"{"class":"Direct","dial_info":{"kind":"FOO","socket_address":"10.0.0.1:443","request":"foo://10.0.0.1:443/"}}"#;
    let detail: DialInfoDetail =
        serde_json::from_str(json).expect("should deserialize DialInfoDetail with unknown kind");
    assert!(matches!(detail.dial_info, DialInfo::Unknown));
    assert!(!detail.dial_info.is_valid());
}

/// Simulate a bootstrap v1 response containing a mix of known and unknown dial info types.
/// The entire response should deserialize successfully; the unknown entries should be
/// identifiable via pattern matching and `is_valid()`.
pub async fn test_mixed_known_and_unknown_in_vec() {
    let json = r#"[
        {"class":"Direct","dial_info":{"kind":"UDP","socket_address":{"address":{"IPV4":"1.2.3.4"},"port":5150}}},
        {"class":"Direct","dial_info":{"kind":"FOO","socket_address":{"address":{"IPV4":"1.2.3.4"},"port":443},"request":"foo://1.2.3.4:443/"}},
        {"class":"Direct","dial_info":{"kind":"TCP","socket_address":{"address":{"IPV4":"1.2.3.4"},"port":5150}}},
        {"class":"Direct","dial_info":{"kind":"BAR","socket_address":{"address":{"IPV4":"1.2.3.4"},"port":443},"request":"bar://1.2.3.4:443/"}}
    ]"#;

    let details: Vec<DialInfoDetail> =
        serde_json::from_str(json).expect("should deserialize vec with mixed known/unknown");

    assert_eq!(details.len(), 4);

    // First entry (UDP) should be known and valid
    assert!(matches!(details[0].dial_info, DialInfo::UDP(_)));

    // Second entry (FOO) should be Unknown
    assert!(matches!(details[1].dial_info, DialInfo::Unknown));
    assert!(!details[1].dial_info.is_valid());

    // Third entry (TCP) should be known and valid
    assert!(matches!(details[2].dial_info, DialInfo::TCP(_)));

    // Fourth entry (BAR) should be Unknown
    assert!(matches!(details[3].dial_info, DialInfo::Unknown));
    assert!(!details[3].dial_info.is_valid());

    // Filtering out unknowns should leave only the known entries
    let known_details: Vec<_> = details
        .iter()
        .filter(|detail| detail.dial_info.is_valid())
        .collect();
    assert_eq!(known_details.len(), 2);
}

/// Verify that `DialInfo::Unknown` accessor methods return safe defaults.
pub async fn test_unknown_accessors_return_defaults() {
    let dial_info = DialInfo::Unknown;

    assert_eq!(dial_info.port(), 0);
    assert_eq!(dial_info.socket_address(), SocketAddress::default());
    assert_eq!(dial_info.request(), None);
    assert_eq!(dial_info.protocol_type(), ProtocolType::UDP);
}

pub async fn test_all() {
    test_known_variant_roundtrips().await;
    test_unknown_kind_deserializes().await;
    test_unknown_is_not_valid().await;
    test_unknown_does_not_match_filter().await;
    test_detail_with_unknown_deserializes().await;
    test_mixed_known_and_unknown_in_vec().await;
    test_unknown_accessors_return_defaults().await;
}

// TODO Review the tests 
use std::net::{IpAddr, Ipv4Addr};
use bytes::Bytes;
use holo_pim::packet::hello::{HelloMsg, HelloOption, UnicastAddress};

/* HelloOption */

#[test]
fn holdtime_roundtrip() {
    let original = HelloOption::Holdtime(30);
    let encoded = original.encode();
    let decoded = HelloOption::decode(
        u16::from_be_bytes([encoded[0], encoded[1]]),
        &encoded[4..],
    ).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn dr_priority_roundtrip() {
    let original = HelloOption::DRPriority(5);
    let encoded = original.encode();
    let decoded = HelloOption::decode(
        u16::from_be_bytes([encoded[0], encoded[1]]),
        &encoded[4..],
    ).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn lan_prune_delay_roundtrip_t_true() {
    let original = HelloOption::LanPruneDelay {
        t: true,
        propagation_delay: 500,
        override_interval: 2000,
    };
    let encoded = original.encode();
    let decoded = HelloOption::decode(
        u16::from_be_bytes([encoded[0], encoded[1]]),
        &encoded[4..],
    ).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn lan_prune_delay_roundtrip_t_false() {
    let original = HelloOption::LanPruneDelay {
        t: false,
        propagation_delay: 500,
        override_interval: 2000,
    };
    let encoded = original.encode();
    let decoded = HelloOption::decode(
        u16::from_be_bytes([encoded[0], encoded[1]]),
        &encoded[4..],
    ).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn address_list_roundtrip() {
    let original = HelloOption::AddressList(vec![
        UnicastAddress { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)) },
        UnicastAddress { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)) },
    ]);
    let encoded = original.encode();
    let decoded = HelloOption::decode(
        u16::from_be_bytes([encoded[0], encoded[1]]),
        &encoded[4..],
    ).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn address_list_rejects_mismatched_families() {
    let mixed = HelloOption::AddressList(vec![
        UnicastAddress { addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)) },
    ]);
    // manually build a value buffer with one v4 + one v6 address back to back,
    // since encode() itself doesn't currently block constructing this
    let mut data = mixed.encode()[4..].to_vec();
    let v6 = UnicastAddress { addr: "::1".parse().unwrap() };
    data.extend_from_slice(&v6.encode());

    assert!(matches!(
        HelloOption::decode(option_type::ADDRESSLIST, &data),
        Err(DecodeError::MismatchedAddressFamily)
    ));
}

#[test]
fn unknown_option_preserved() {
    let raw_value = Bytes::from_static(&[0xAA, 0xBB, 0xCC]);
    let original = HelloOption::Unknown {
        option_type: 99,
        option_length: 3,
        value: raw_value.clone(),
    };
    let encoded = original.encode();
    let decoded = HelloOption::decode(99, &encoded[4..]).unwrap();
    assert!(matches!(decoded, HelloOption::Unknown { option_type: 99, value, .. } if value == raw_value));
}

/* HelloMsg (the TLV loop) */

#[test]
fn hello_msg_empty_options_roundtrip() {
    let original = HelloMsg { options: vec![] };
    let encoded = original.encode();
    assert!(encoded.is_empty());
    let decoded = HelloMsg::decode(&encoded).unwrap();
    assert_eq!(decoded.options.len(), 0);
}

#[test]
fn hello_msg_multiple_options_roundtrip() {
    let original = HelloMsg {
        options: vec![
            HelloOption::Holdtime(30),
            HelloOption::DRPriority(5),
        ],
    };
    let encoded = original.encode();
    let decoded = HelloMsg::decode(&encoded).unwrap();
    assert_eq!(decoded.options, original.options);
}

#[test]
fn hello_msg_decode_rejects_truncated_option_value() {
    // claims a 4-byte value but only supplies 1
    let data = [0x00, 0x13, 0x00, 0x04, 0xFF];
    assert!(matches!(HelloMsg::decode(&data), Err(DecodeError::IncompletePacket)));
}
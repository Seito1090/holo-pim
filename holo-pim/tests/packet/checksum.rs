/* Tests for the ip checksum as defined in RFC 1071, used by PIM packets*/
use holo_pim::checksum::{compute, compute_ipv6};
use std::net::Ipv6Addr;

#[test]
fn computes_rfc1071_example() {
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];

    assert_eq!(compute(&data), 0x220d);
}

#[test]
fn computes_pim_like_example() {
    let data = [0x00, 0x01, 0x00, 0x00, 0xf4, 0xf5, 0xf6, 0xf7];

    assert_eq!(compute(&data), 0x1411);
}

#[test]
fn verifies_checksum_when_included_in_input() {
    let data = [0x00, 0x01, 0x14, 0x11, 0xf4, 0xf5, 0xf6, 0xf7];

    assert_eq!(compute(&data), 0x0000);
}

#[test]
fn handles_empty_input() {
    assert_eq!(compute(&[]), 0xffff);
}

#[test]
fn pads_odd_length_input_with_zero_byte() {
    assert_eq!(compute(&[0x01]), 0xfeff);
    assert_eq!(compute(&[0x01, 0x02, 0x03]), 0xfbfd);
}

#[test]
fn folds_end_around_carry() {
    assert_eq!(compute(&[0xff, 0xff, 0xff, 0xff]), 0x0000);
}

#[test]
fn ipv6_checksum_includes_pseudo_header() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000d);
    let data = [0x20, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];

    // Includes:
    // - source address
    // - destination address
    // - upper-layer length
    // - Next Header = 103
    // - PIM payload
    assert_eq!(compute_ipv6(&data, src, dst, data.len()), 0xaec0);
}

#[test]
fn ipv6_checksum_uses_register_header_length() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000d);

    // Simulated PIM Register data with more than the 8-byte Register
    // header so that the length behavior is observable.
    let data = [
        0x20, 0x00, 0x00, 0x00, // PIM header
        0x01, 0x02, 0x03, 0x04, // Register header remainder
        0x05,                    // Encapsulated payload
    ];

    let register_checksum = compute_ipv6(&data, src, dst, 8);
    let complete_message_checksum = compute_ipv6(&data, src, dst, data.len());

    assert_eq!(register_checksum, 0xaec0);
    assert_eq!(complete_message_checksum, 0xa9bf);
    assert_ne!(register_checksum, complete_message_checksum);
}

#[test]
fn ipv6_checksum_handles_odd_length_payload() {
    let src = Ipv6Addr::LOCALHOST;
    let dst = Ipv6Addr::UNSPECIFIED;
    let data = [0x01, 0x02, 0x03, 0x04, 0x05];

    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&src.octets());
    pseudo_header.extend_from_slice(&dst.octets());
    pseudo_header.extend_from_slice(&(data.len() as u32).to_be_bytes());
    pseudo_header.extend_from_slice(&[0, 0, 0, 103]);
    pseudo_header.extend_from_slice(&data);

    // The final byte must be padded as the low-order byte of the last
    // 16-bit word, matching RFC 1071 checksum behavior.
    assert_eq!(
        compute_ipv6(&data, src, dst, data.len()),
        compute(&pseudo_header)
    );
}

#[test]
fn ipv6_checksum_changes_when_addresses_change() {
    let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let other_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let dst = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000d);
    let data = [0x20, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04];

    assert_ne!(
        compute_ipv6(&data, src, dst, data.len()),
        compute_ipv6(&data, other_src, dst, data.len())
    );
}
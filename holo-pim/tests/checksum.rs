use holo_pim::checksum::compute;

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

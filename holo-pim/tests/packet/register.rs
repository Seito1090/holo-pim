/* Tests for Register message bodies, flags, reserved bits, and payload rules. */
use holo_pim::packet::{RegisterMsg};
use holo_pim::errors::DecodeError;

#[test]
fn truncated_register_body_rejected(){
    for length in 0..4 {
        let data = vec![0u8; length];

        assert!(
            matches!(RegisterMsg::decode(&data), Err(DecodeError::IncompletePacket)),
            "unexpected result for truncated Register body length {length}"
        );
    }
}

#[test]
fn register_decode_rejects_reserved_bits() {
    assert!(matches!(
        RegisterMsg::decode(&[0x00, 0x00, 0x00, 0x01]),
        Err(DecodeError::InvalidReserved(1))
    ));

    assert!(matches!(
        RegisterMsg::decode(&[0x00, 0x00, 0x01, 0x00]),
        Err(DecodeError::InvalidReserved(0x100))
    ));

    assert!(matches!(
        RegisterMsg::decode(&[0x00, 0x3f, 0xff, 0xff]),
        Err(DecodeError::InvalidReserved(0x3f_ff_ff))
    ));
}

#[test]
fn null_register_has_no_payload() {
    let data = [0x40, 0x00, 0x00, 0x00];

    let decoded = RegisterMsg::decode(&data).unwrap();

    assert!(decoded.null_bit);
    assert!(decoded.packet.is_empty());
}
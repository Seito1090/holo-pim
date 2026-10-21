use crate::errors::DecodeError;
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug)]
pub struct RegisterMsg {
    pub border_bit: bool, 
    pub null_bit: bool,
    pub packet: Bytes,
}

impl RegisterMsg {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u32(((self.border_bit as u32) << 31) | ((self.null_bit as u32) << 30));
        buf.extend_from_slice(&self.packet);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        // Minimum register body lenght is 4 bytes.
        if data.len() < 4 {
            return Err(DecodeError::IncompletePacket);
        }

        let register_header = u32::from_be_bytes(data[..4].try_into().unwrap());

        // Check reserved bits are zeroed
        // NOTE: this is stricter than RFC7761 requires but helps for now. We can relax this later if needed. (They should still be set to zero upon transmitting but the RFC doesn't require receivers to reject packets with non-zero reserved bits.)
        if register_header & 0x3FFF_FFFF != 0 { 
            return Err(DecodeError::InvalidReserved(
                register_header & 0x3FFF_FFFF,
            ));
        }

        let border_bit = (register_header >> 31) != 0;
        let null_bit = (register_header >> 30) != 0;
        let packet = Bytes::copy_from_slice(&data[4..]);

        // NOTE: the description of the null bit in RFC7761 implicitelly suggests that if the null bit is set, the packet must be empty and if the null bit is not set, the packet must not be empty. However, it doesn't state that this check should be enforced in the decoding process. The following check is commented out for now, but it could be re-enabled if we want to enforce this rule in the future.
        /*if null_bit != packet.is_empty() {
            return Err(DecodeError::InvalidRegisterPayload);
        }*/

        Ok(RegisterMsg { 
            border_bit, 
            null_bit, 
            packet
        })
    }
}

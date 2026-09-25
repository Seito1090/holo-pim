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
        // add checks, reserved 2 should be all 0s and data should contain a multicast data packet, so size is min 4 bytes
        let header = *&data.first().ok_or(DecodeError::IncompletePacket)?;
        let border_bit = (header >> 7) != 0;
        let null_bit = (header >> 6) != 0;
        let packet = Bytes::copy_from_slice(&data[4..]);

        Ok(RegisterMsg { 
            border_bit, 
            null_bit, 
            packet
        })
    }
}

// tests, mainly just check if small packet is ignored and same with ones with reserved not null
use crate::{address::{GroupAddress, UnicastAddress}, errors::DecodeError};
use bytes::{BufMut, BytesMut};

#[derive(Debug)]
pub struct RegisterStopMsg {
    pub group_address: GroupAddress,
    pub source_address: UnicastAddress,
}

impl RegisterStopMsg {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put(self.group_address.encode());
        buf.put(self.source_address.encode());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        // same remark as in register.rs
        let (group_address, gsize) = GroupAddress::decode(data)?;
        let (source_address, _ssize) = UnicastAddress::decode(&data[gsize..])?;
        Ok(RegisterStopMsg { group_address, source_address})
    }
}
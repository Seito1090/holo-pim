use crate::{errors::DecodeError, address::{UnicastAddress, GroupAddress}};
use bytes::{BufMut, BytesMut};

#[derive(Debug)]
pub struct AssertMsg {
    pub group_address: GroupAddress,
    pub source_address: UnicastAddress,
    pub rp_bit: bool,
    pub metric_preference: u32,
    pub metric: u32,
}

impl AssertMsg {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&self.group_address.encode());
        buf.extend_from_slice(&self.source_address.encode());
        buf.put_u32((self.rp_bit as u32) << 31 | self.metric_preference);
        buf.put_u32(self.metric);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let (group_address, group_len) = GroupAddress::decode(data)?;
        let (source_address, source_len)= UnicastAddress::decode(&data[group_len..])?;

        let reste: &[u8] = &data[group_len+source_len..];
        let rp_bit: bool = (reste[0] & 0x80) != 0;

        let metric_preference_bytes: [u8; 4] = reste.get(0..4)
                                                    .ok_or(DecodeError::IncompletePacket)?
                                                    .try_into().unwrap();
        let metric_preference: u32 = u32::from_be_bytes(metric_preference_bytes) & 0x7FFFFFFF;

        let metric_bytes: [u8; 4] = reste.get(4..8)
                                .ok_or(DecodeError::IncompletePacket)?
                                .try_into().unwrap();
        let metric:u32 = u32::from_be_bytes(metric_bytes.try_into().unwrap());

        Ok(AssertMsg { 
            group_address, 
            source_address, 
            rp_bit, 
            metric_preference, 
            metric 
        })
    }
}
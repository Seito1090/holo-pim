use crate::errors::DecodeError;
use bytes::{
    //BufMut, Bytes, 
    BytesMut};

#[derive(Debug)]
pub struct CandidateRpAdvertisementMsg {

}

impl CandidateRpAdvertisementMsg {
    pub fn encode(&self) -> BytesMut {
        let buf = BytesMut::new();
        buf
    }
    pub fn decode(_data: &[u8]) -> Result<Self, DecodeError> {
        Ok(CandidateRpAdvertisementMsg {})
    }
}
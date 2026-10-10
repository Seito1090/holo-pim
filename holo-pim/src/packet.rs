// This manages the encoding and decoding of PIM packets as described in section 4.9 of RFC 7761
use bytes::{BufMut, BytesMut};
use crate::checksum;
use crate::errors::DecodeError; 

// Different message types
mod assert;
mod hello;
mod register;
mod register_stop;
mod join_prune;
mod bootstrap;
mod candidate_rp_advertisement;

pub use assert::AssertMsg;
pub use bootstrap::BootstrapMsg;
pub use candidate_rp_advertisement::CandidateRpAdvertisementMsg;
pub use hello::HelloMsg;
pub use join_prune::{JoinPruneMsg, MulticastGroup};
pub use register::RegisterMsg;
pub use register_stop::RegisterStopMsg;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PimType {
    Hello = 0,
    Register = 1,
    RegisterStop = 2,
    JoinPrune = 3,
    Bootstrap = 4,
    Assert = 5,
    Graft = 6,
    GraftAck = 7,
    CandidateRpAdvertisement = 8,  
}

impl TryFrom<u8> for PimType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PimType::Hello),
            1 => Ok(PimType::Register),
            2 => Ok(PimType::RegisterStop),
            3 => Ok(PimType::JoinPrune),
            4 => Ok(PimType::Bootstrap),
            5 => Ok(PimType::Assert),
            6 => Ok(PimType::Graft),
            7 => Ok(PimType::GraftAck),
            8 => Ok(PimType::CandidateRpAdvertisement),
            _ => Err(DecodeError::InvalidMessageType(value)),
        }
    }
}

impl std::fmt::Display for PimType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result{
        let name = match self {
            PimType::Hello => "Hello",
            PimType::Register => "Register",
            PimType::RegisterStop => "Register Stop",
            PimType::JoinPrune => "Join Prune",
            PimType::Bootstrap => "Bootstrap",
            PimType::Assert => "Assert",
            PimType::Graft => "Graft",
            PimType::GraftAck => "Graft Ack",
            PimType::CandidateRpAdvertisement => "Candidate RP Advertisement",
        };
        write!(f, "{name}")
    }
}


pub enum Message {
    Hello(HelloMsg),
    Register(RegisterMsg),
    RegisterStop(RegisterStopMsg),
    JoinPrune(JoinPruneMsg),
    Bootstrap(BootstrapMsg),
    Assert(AssertMsg),
    //Graft(GraftMsg),
    //GraftAck(GraftAckMsg),
    CandidateRpAdvertisement(CandidateRpAdvertisementMsg),  
}

impl Message {
    pub fn encode(&self) -> BytesMut {
        let (pim_type, body) = match self {
            Message::Hello(m)                    => (PimType::Hello, m.encode()),
            Message::Register(m)                 => (PimType::Register, m.encode()),
            Message::RegisterStop(m)             => (PimType::RegisterStop, m.encode()),
            Message::JoinPrune(m)                => (PimType::JoinPrune, m.encode()),
            Message::Bootstrap(m)                => (PimType::Bootstrap, m.encode()),
            Message::Assert(m)                   => (PimType::Assert, m.encode()),
            Message::CandidateRpAdvertisement(m) => (PimType::CandidateRpAdvertisement, m.encode()),
        };

        // Common part of header 
        let mut buf = BytesMut::new();
        buf.put_u8((2 << 4) | (pim_type as u8)); // NOTE, in the future the version might change, maybe doing it as a field or argument might be a better long term solution

        // Reserved
        buf.put_u8(0);

        // Temporary checksum value
        buf.put_u16(0);

        // Body of the message 
        buf.extend_from_slice(&body);

        // Compute the checksum
        let chk: u16;
        match pim_type {
            PimType::Register => {chk = checksum::compute(&buf[..8])}
            _ => {chk = checksum::compute(&buf)}
        }
        buf[2..4].copy_from_slice(&chk.to_be_bytes());
        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        // Common part is 4 bytes, anything less is defacto, wrong
        if 4 > data.len() {
            return Err(DecodeError::IncompletePacket)
        }

        // Version
        let version: u8 = data[0] >> 4;
        if 2 != version {
            return Err(DecodeError::InvalidVersion(version))
        }

        // Type
        let raw_type: u8 = data[0] & 0x0F;
        let msg_type: PimType = PimType::try_from(raw_type)?;

        // Reserved, should be 0
        let reserved: u8 = data[1];
        if 0 != reserved {
            return Err(DecodeError::InvalidReserved(reserved))
        }
    
        // Checksum 
        let checksum: u16;
        match msg_type {
            PimType::Register => {checksum = checksum::compute(&data[..8])}
            _ => {checksum = checksum::compute(&data)}
        }
        
        if checksum != 0x0000 {
            return Err(DecodeError::InvalidChecksum)
        }

        // Actual body of the packet
        let body: &[u8] = &data[4..];
        
        Ok(match msg_type {
            PimType::Hello                    => Message::Hello(HelloMsg::decode(body)?),
            PimType::Register                 => Message::Register(RegisterMsg::decode(body)?),
            PimType::RegisterStop             => Message::RegisterStop(RegisterStopMsg::decode(body)?),
            PimType::JoinPrune                => Message::JoinPrune(JoinPruneMsg::decode(body)?),
            PimType::Bootstrap                => Message::Bootstrap(BootstrapMsg::decode(body)?),
            PimType::Assert                   => Message::Assert(AssertMsg::decode(body)?),
            PimType::CandidateRpAdvertisement => Message::CandidateRpAdvertisement(CandidateRpAdvertisementMsg::decode(body)?),
            PimType::Graft|PimType::GraftAck  => return Err(DecodeError::UnsupportedMessage(msg_type)),
        })
    }
}

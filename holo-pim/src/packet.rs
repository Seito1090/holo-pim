/* This manages the encoding and decoding of PIM packets as described in section 4.9 of RFC 7761 */
use crate::checksum;
use crate::errors::DecodeError;
use bytes::{BufMut, BytesMut};
use std::net::Ipv6Addr;

/* Constants */
pub const PIM_VERSION: u8 = 2;
pub const PIM_HEADER_LEN: usize = 4;
pub const PIM_VERSION_SHIFT: u8 = 4;
pub const PIM_TYPE_MASK: u8 = 0x0f;

// Different message types
mod assert;
mod bootstrap;
mod candidate_rp_advertisement;
mod hello;
mod join_prune;
mod register;
mod register_stop;

pub use assert::AssertMsg;
pub use bootstrap::BootstrapMsg;
pub use candidate_rp_advertisement::CandidateRpAdvertisementMsg;
pub use hello::{HelloMsg, HelloOption};
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

// PIM packet header format
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |PIM Ver| Type  | Reserved      | Checksum                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

impl Message {
    pub fn encode(&self) -> BytesMut {
        self.encode_with_checksum(None)
    }

    pub fn encode_ipv6(&self, src: Ipv6Addr, dst: Ipv6Addr) -> BytesMut {
        self.encode_with_checksum(Some((src, dst)))
    }

    fn encode_with_checksum(
        &self,
        ipv6: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> BytesMut {
        // Determine the type of message and encode the body
        let (pim_type, body) = match self {
            Message::Hello(m) => (PimType::Hello, m.encode()),
            Message::Register(m) => (PimType::Register, m.encode()),
            Message::RegisterStop(m) => (PimType::RegisterStop, m.encode()),
            Message::JoinPrune(m) => (PimType::JoinPrune, m.encode()),
            Message::Bootstrap(m) => (PimType::Bootstrap, m.encode()),
            Message::Assert(m) => (PimType::Assert, m.encode()),
            Message::CandidateRpAdvertisement(m) => {
                (PimType::CandidateRpAdvertisement, m.encode())
            }
        };

        let mut buf = BytesMut::new();

        // --- Common part of header ---
        buf.put_u8((PIM_VERSION << PIM_VERSION_SHIFT) | (pim_type as u8)); // Version and type
        buf.put_u8(0); // Reserved
        buf.put_u16(0); // Temporary checksum value
                        // --- End of common part ---

        buf.extend_from_slice(&body); // Body of the message

        // Compute the checksum
        let chk: u16;
        let checksum_len = if pim_type == PimType::Register {
            8
        } else {
            buf.len()
        };
        chk = match ipv6 {
            Some((src, dst)) => {
                checksum::compute_ipv6(&buf, src, dst, checksum_len)
            }
            None => checksum::compute(&buf[..checksum_len]),
        };
        buf[2..4].copy_from_slice(&chk.to_be_bytes()); // Update the checksum in the buffer

        buf
    }

    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        Self::decode_with_checksum(data, None)
    }

    pub fn decode_ipv6(
        data: &[u8],
        src: Ipv6Addr,
        dst: Ipv6Addr,
    ) -> Result<Self, DecodeError> {
        Self::decode_with_checksum(data, Some((src, dst)))
    }

    fn decode_with_checksum(
        data: &[u8],
        ipv6: Option<(Ipv6Addr, Ipv6Addr)>,
    ) -> Result<Self, DecodeError> {
        // Common part is 4 bytes, anything less is defacto, wrong
        if PIM_HEADER_LEN > data.len() {
            return Err(DecodeError::IncompletePacket);
        }

        // Version check
        let version: u8 = data[0] >> PIM_VERSION_SHIFT;
        if PIM_VERSION != version {
            return Err(DecodeError::InvalidVersion(version));
        }

        // Type check
        let raw_type: u8 = data[0] & PIM_TYPE_MASK;
        let msg_type: PimType = PimType::try_from(raw_type)?;

        // A Register message has a minimum length of 8 bytes
        // This check is used to avoid panics when computing the checksum for Register messages, which only uses the first 8 bytes of the packet.
        if msg_type == PimType::Register && data.len() < 8 {
            return Err(DecodeError::IncompletePacket);
        }

        // Reserved, should be 0
        // NOTE: this is stricter than RFC7761 but could help discard a malformed packet more quickly.
        let reserved: u8 = data[1];
        if 0 != reserved {
            return Err(DecodeError::InvalidReserved(reserved as u32));
        }

        // Checksum
        let checksum: u16;
        let checksum_len = if msg_type == PimType::Register {
            8
        } else {
            data.len()
        };
        checksum = match ipv6 {
            Some((src, dst)) => {
                checksum::compute_ipv6(data, src, dst, checksum_len)
            }
            None => checksum::compute(&data[..checksum_len]),
        };

        if checksum != 0x0000 {
            return Err(DecodeError::InvalidChecksum);
        }

        // Actual body of the packet
        let body: &[u8] = &data[4..];

        Ok(match msg_type {
            PimType::Hello => Message::Hello(HelloMsg::decode(body)?),
            PimType::Register => Message::Register(RegisterMsg::decode(body)?),
            PimType::RegisterStop => {
                Message::RegisterStop(RegisterStopMsg::decode(body)?)
            }
            PimType::JoinPrune => {
                Message::JoinPrune(JoinPruneMsg::decode(body)?)
            }
            PimType::Bootstrap => {
                Message::Bootstrap(BootstrapMsg::decode(body)?)
            }
            PimType::Assert => Message::Assert(AssertMsg::decode(body)?),
            PimType::CandidateRpAdvertisement => {
                Message::CandidateRpAdvertisement(
                    CandidateRpAdvertisementMsg::decode(body)?,
                )
            }
            PimType::Graft | PimType::GraftAck => {
                return Err(DecodeError::UnsupportedMessage(msg_type))
            }
        })
    }
}

use bytes::TryGetError;
use crate::packet::PimType;


#[derive(Debug)]
pub enum DecodeError {
    IncompletePacket,
    InvalidVersion(u8),
    InvalidMessageType(u8),
    InvalidChecksum,
    InvalidEncoding(u8),
    InvalidReserved(u8),
    UnsupportedMessage(PimType),
    InvalidAddressFamily(u8),
    MismatchedAddressFamily,
}

// ===== impl DecodeError =====

// InvalidReserved(u8), InvaildChecksumk,
impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::IncompletePacket => {
                write!(f, "Incomplete packet")
            }
            DecodeError::InvalidVersion(version) => {
                write!(f, "Invalid BFD version: {version}")
            }
            DecodeError::InvalidMessageType(msg_type) => {
                write!(f, "Invalid packet length: {msg_type}")
            }
            DecodeError::InvalidChecksum => {
                write!(f, "Invalid standard checksum")
            }
            DecodeError::InvalidEncoding(value) => {
                write!(f, "Invalid encoding value {value}, should be 0 ")
            }
            DecodeError::UnsupportedMessage(pim_type) => {
                write!(f, "Unsupported message type found: {pim_type}")
            }
            DecodeError::InvalidAddressFamily(family) => {
                write!(f, "Invalid family used: {family}")
            }
            DecodeError::InvalidReserved(value) => {
                write!(f, "Invalid reserved bits found: {value:#x}")
            }
            DecodeError::MismatchedAddressFamily => {
                write!(f, "Mismatched address families found.")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<TryGetError> for DecodeError {
    fn from(_error: TryGetError) -> DecodeError {
        DecodeError::IncompletePacket
    }
}
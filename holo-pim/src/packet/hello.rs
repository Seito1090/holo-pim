use crate::{address::{self, UnicastAddress}, errors::DecodeError};
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Debug, PartialEq)]
pub struct HelloMsg {
    pub options: Vec<HelloOption>
} 

impl HelloMsg {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        for option in &self.options {
            buf.extend_from_slice(&option.encode());
        }
        buf
    }
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let mut options = Vec::new();
        let mut remaining = data;
        while remaining.len() >= 4{
            let option_type = u16::from_be_bytes([remaining[0], remaining[1]]);
            let option_len = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;
            let option_value = remaining.get(4..4+option_len).ok_or(DecodeError::IncompletePacket)?;
            options.push(HelloOption::decode(option_type, option_value)?);
            remaining = &remaining[4+option_len..];
        }
        Ok(HelloMsg { options })
    }
}

mod option_type {
    pub const HOLDTIME: u16 = 1;
    pub const LANPRUNEDELAY: u16 = 2;
    pub const DRPRIORITY: u16 = 19;
    pub const GENERATIONID: u16 = 20;
    pub const ADDRESSLIST: u16 = 24;
}

#[derive(Debug, PartialEq)]
pub enum HelloOption {
    Holdtime(u16),
    LanPruneDelay {t:bool, propagation_delay: u16, override_interval: u16},
    DRPriority(u32),
    GeneratoinId(u32),
    AddressList(Vec<UnicastAddress>),
    Unknown {option_type: u16, option_length: u16, value: Bytes},
}

impl HelloOption {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        let mut value = BytesMut::new();
        let (op_type, op_value) = match self {
            HelloOption::Holdtime(h_time) => {
                value.put_u16(*h_time);
                (option_type::HOLDTIME, value)
            },
            HelloOption::LanPruneDelay { t, propagation_delay, override_interval } => {
                let propagation_delay: u16 = ((*t as u16) << 15) | propagation_delay;
                let override_interval: u16 = *override_interval;
                value.put_u16(propagation_delay);
                value.put_u16(override_interval);
                (option_type::LANPRUNEDELAY, value)
            },
            HelloOption::DRPriority(priority) => {
                value.put_u32(*priority);
                (option_type::DRPRIORITY, value)
            },
            HelloOption::GeneratoinId(id) => {
                value.put_u32(*id);
                (option_type::GENERATIONID, value)
            },
            HelloOption::AddressList(unicast_addrs) => {
                // Note : every addr in one list has to be of the same family 
                for addr in unicast_addrs {
                    value.extend_from_slice(&addr.encode());
                }
                (option_type::ADDRESSLIST, value)
            },
            HelloOption::Unknown { option_type, option_length: _, value } => {
                (*option_type, BytesMut::from(&value[..]))
            }
        };
        buf.put_u16(op_type);
        buf.put_u16(op_value.len() as u16);
        buf.put(op_value);
        buf
    }

    pub fn decode(op_type: u16, data: &[u8]) -> Result<Self, DecodeError> {
        Ok(match op_type {
            option_type::HOLDTIME => { 
                HelloOption::Holdtime(u16::from_be_bytes([data[0], data[1]]))
            },
            option_type::LANPRUNEDELAY => {
                let t = (data[0] >> 7) != 0;
                let propagation_delay = u16::from_be_bytes([data[0] & 0x7F, data[1]]);
                let override_interval = u16::from_be_bytes([data[2], data[3]]);
                HelloOption::LanPruneDelay {
                    t, 
                    propagation_delay, 
                    override_interval 
                }
            },
            option_type::DRPRIORITY => {
                HelloOption::DRPriority(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            },
            option_type::GENERATIONID => {
                HelloOption::GeneratoinId(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            },
            option_type::ADDRESSLIST => {
                let mut addresses = Vec::new();
                let mut remaining = data;
                
                while !remaining.is_empty(){
                    let (addr, consumed) = UnicastAddress::decode(remaining)?;
                    addresses.push(addr);
                    remaining = &remaining[consumed..];
                }

                if let Some(first) = addresses.first() {
                    let fam = address::family_of(&first.addr); 
                    for addr in &addresses{
                        if address::family_of(&addr.addr) != fam {
                            return Err(DecodeError::MismatchedAddressFamily);
                        }
                    }
                }
                HelloOption::AddressList(addresses)
            },
            _ => HelloOption::Unknown { 
                option_type: op_type, 
                option_length: data.len() as u16, 
                value: Bytes::copy_from_slice(data)
            }
        })
    }
}

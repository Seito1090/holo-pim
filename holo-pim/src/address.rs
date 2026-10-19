use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use bytes::{BufMut, BytesMut};
use crate::errors::DecodeError;

// Encoded Unicast Address
mod addr_family {
    pub const IPV4: u8 = 1;
    pub const IPV6: u8 = 2;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnicastAddress {
    pub addr: IpAddr,
}

impl UnicastAddress {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        match self.addr {
            IpAddr::V4(v4) => {
                buf.put_u8(addr_family::IPV4); 
                buf.put_u8(0); // encoding type is set to 0 as per rfc 7761
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u8(addr_family::IPV6);
                buf.put_u8(0);
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError>{
        let family = *data.first().ok_or(DecodeError::IncompletePacket)?;
        let encoding = *data.get(1).ok_or(DecodeError::IncompletePacket)?;
        if 0 != encoding {
            return Err(DecodeError::InvalidEncoding(encoding));
        }
        let (addr, addr_len) = decode_helper(family, &data[2..])?;
        Ok((UnicastAddress{addr},2 + addr_len))
    }
}

// Encoded Group Address
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupAddress {
    pub addr: IpAddr,
    pub b_bit: bool,
    pub z_bit: bool, 
    pub mask_byte: u8,
}

impl GroupAddress {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        match self.addr {
            IpAddr::V4(v4) => {
                buf.put_u8(addr_family::IPV4); 
                buf.put_u8(0); // encoding type is set to 0 as per rfc 7761
                buf.put_u8(((self.b_bit as u8) << 7) | (self.z_bit as u8)); // b/z bits and reserved
                buf.put_u8(self.mask_byte);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u8(addr_family::IPV6);
                buf.put_u8(0);
                buf.put_u8(((self.b_bit as u8) << 7) | (self.z_bit as u8));
                buf.put_u8(self.mask_byte);
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError>{
        let family = *data.first().ok_or(DecodeError::IncompletePacket)?;
        let encoding = *data.get(1).ok_or(DecodeError::IncompletePacket)?;
        if 0 != encoding {
            return Err(DecodeError::InvalidEncoding(encoding));
        }
        let reserved = *data.get(2).ok_or(DecodeError::IncompletePacket)?;
        if (reserved & 0x7E) != 0x00{
            return Err(DecodeError::InvalidReserved(reserved));
        }
        let b_bit: bool = (reserved & 0x80) != 0x00;
        let z_bit: bool = (reserved & 0x01) != 0x00; 
        let mask_byte: u8 = *data.get(3).ok_or(DecodeError::IncompletePacket)?;
        let (addr, addr_len) = decode_helper(family, &data[4..])?;
        Ok((GroupAddress{addr, b_bit, z_bit, mask_byte}, 4 + addr_len))
    }
}

// Encoded Source Address
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceAddress {
    pub addr: IpAddr,
    pub s_bit: bool,
    pub w_bit: bool,   
    pub r_bit: bool, 
    pub mask_byte: u8,
} 

impl SourceAddress {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        match self.addr {
            IpAddr::V4(v4) => {
                buf.put_u8(addr_family::IPV4); 
                buf.put_u8(0); // encoding type is set to 0 as per rfc 7761
                buf.put_u8(((self.s_bit as u8) << 2)| ((self.w_bit as u8) << 1) | (self.r_bit as u8));
                buf.put_u8(self.mask_byte);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u8(addr_family::IPV6);
                buf.put_u8(0);
                buf.put_u8(((self.s_bit as u8) << 2) | ((self.w_bit as u8) << 1) | (self.r_bit as u8));
                buf.put_u8(self.mask_byte);
                buf.extend_from_slice(&v6.octets());
            }
        }
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError>{
        let family = *data.first().ok_or(DecodeError::IncompletePacket)?;
        let encoding = *data.get(1).ok_or(DecodeError::IncompletePacket)?;
        if 0 != encoding {
            return Err(DecodeError::InvalidEncoding(encoding));
        }
        let reserved = *data.get(2).ok_or(DecodeError::IncompletePacket)?; 
        if (reserved & 0xF8) != 0x00{
            return Err(DecodeError::InvalidReserved(reserved));
        }
        let s_bit: bool = (reserved & 0x04) != 0x00;
        let w_bit: bool = (reserved & 0x02) != 0x00;
        let r_bit: bool = (reserved & 0x01) != 0x00;
        let mask_byte: u8 = *data.get(3).ok_or(DecodeError::IncompletePacket)?;
        let (addr, addr_len) = decode_helper(family, &data[4..])?;
        Ok((SourceAddress{addr, s_bit, w_bit, r_bit, mask_byte}, 4 + addr_len))
    }
}

fn decode_helper(family: u8, data: &[u8]) -> Result<(IpAddr, usize), DecodeError> {
    match family {
        addr_family::IPV4 => {
            let address_bytes: [u8; 4] = data.get(..4)
                            .ok_or(DecodeError::IncompletePacket)?
                            .try_into().unwrap();
            Ok((IpAddr::V4(Ipv4Addr::from(address_bytes)), 4))
        }
        addr_family::IPV6 => {
            let address_bytes: [u8; 16] = data.get(..16)
                            .ok_or(DecodeError::IncompletePacket)?
                            .try_into().unwrap();
            Ok((IpAddr::V6(Ipv6Addr::from(address_bytes)), 16))
        }
        _ => Err(DecodeError::InvalidAddressFamily(family))
    }
}

// Helper function 
pub fn family_of(addr: &IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => 1,
        IpAddr::V6(_) => 2,
    }
}

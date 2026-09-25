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

// Notes for future me, tests cases I want to cover : 
//  - Basic round trip, encode + decode
//  - Byte checks for differnet fields
//  - Wrong input, truncated or outright missing parts, invalid values in general, seperate encode and decode
//  - Size value from decode

// General guide line : 1 test = 1 behavior, test name is explicit in what it tests
#[cfg(test)]
mod tests {
    use super::*;

    // ---- Unicast ----
    #[test]
    fn unicast_ipv4_roundtrip() {
        let original = UnicastAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        let encoded = original.encode();
        let (decoded, consumed) = UnicastAddress::decode(&encoded).unwrap();

        assert_eq!(decoded.addr, original.addr);
        assert_eq!(consumed, encoded.len()); // 1 family + 1 encoding type + 4 address bytes
    }

    #[test]
    fn unicast_ipv6_roundtrip(){
        let original = UnicastAddress{
            addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
        };
        
        let encoded = original.encode();
        let (decoded, consumed) = UnicastAddress::decode(&encoded).unwrap();

        assert_eq!(decoded.addr, original.addr);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn unicast_ipv4_encoded_bytes(){
        let original_v4 = UnicastAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        let encoded_v4 = original_v4.encode();
        assert_eq!(encoded_v4[0], 0x01);
        assert_eq!(encoded_v4[1], 0x00);
    }

    #[test]
    fn unicast_ipv6_encoded_bytes(){
        let original_v6 = UnicastAddress{
            addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
        };
        let encoded_v6 = original_v6.encode();
        assert_eq!(encoded_v6[0], 0x02);
        assert_eq!(encoded_v6[1], 0x00);
    }

    #[test]
    fn unicast_decode_reject_empty_data(){
        assert!(matches!(UnicastAddress::decode(&[]), Err(DecodeError::IncompletePacket)));
    }

    #[test]
    fn unicast_decode_reject_wrong_encoding(){
        let data: [u8; 2] = [1, 1];
        assert!(matches!(UnicastAddress::decode(&data), Err(DecodeError::InvalidEncoding(1))));
    }

    #[test]
    fn unicast_decode_reject_invalid_family(){
        let data: [u8; 6] = [99, 0, 192, 168, 1, 1]; 
        assert!(matches!(UnicastAddress::decode(&data), Err(DecodeError::InvalidAddressFamily(99))));
    }

    #[test]
    fn unicast_decode_reject_short_value(){
        let data: [u8; 4] = [1, 0, 12, 12]; 
        assert!(matches!(UnicastAddress::decode(&data), Err(DecodeError::IncompletePacket)));
    }

    #[test]
    fn unicast_ipv4_decode_reports_correct_address_lenght_and_ignores_trailing_bytes(){
        let mut data = vec![1, 0, 192, 168, 1, 1];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // extra trailing bytes

        let (decoded, consumed) = UnicastAddress::decode(&data).unwrap();
        assert_eq!(consumed, 6); 
        assert_eq!(decoded.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn unicast_ipv6_decode_reports_correct_consumed_and_ignores_trailing_bytes() {
        let mut data = vec![2, 0]; // family=IPv6, encoding=0
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()); // 16 bytes
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // trailing junk

        let (decoded, consumed) = UnicastAddress::decode(&data).unwrap();
        assert_eq!(consumed, 18);
        assert_eq!(decoded.addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn unicast_ipv6_decode_rejects_short_address() {
        let data = [2, 0, 0x10, 0x0c];
        assert!(matches!(UnicastAddress::decode(&data), Err(DecodeError::IncompletePacket)));
    }

    // ---- Group address ----
    #[test]
    fn group_ipv4_roundtrip() {
        let original = GroupAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        };
        let encoded = original.encode();
        let (decoded, consumed) = GroupAddress::decode(&encoded).unwrap();

        assert_eq!(decoded.addr, original.addr);
        assert_eq!(consumed, encoded.len()); // 1 family + 1 encoding type + 4 address bytes
    }

    #[test]
    fn group_ipv6_roundtrip(){
        let original = GroupAddress {
            addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        };
        let encoded = original.encode();
        let (decoded, consumed) = GroupAddress::decode(&encoded).unwrap();

        assert_eq!(decoded.addr, original.addr);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn group_ipv4_encoded_bytes(){
        let original_v4 = GroupAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        };
        let encoded_v4 = original_v4.encode();
        assert_eq!(encoded_v4[0], 0x01);
        assert_eq!(encoded_v4[1], 0x00);
        assert_eq!(encoded_v4[2] & 0x80, 0x00);
        assert_eq!(encoded_v4[2] & 0x01, 0x01);
        assert_eq!(encoded_v4[2] & 0x7E, 0x00);
        assert_eq!(encoded_v4[3], 0x4C);
    }

    #[test]
    fn group_ipv6_encoded_bytes(){
        let original_v6 = GroupAddress {
            addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        };
        let encoded_v6 = original_v6.encode();
        assert_eq!(encoded_v6[0], 0x02);
        assert_eq!(encoded_v6[1], 0x00);
        assert_eq!(encoded_v6[2] & 0x80, 0x00);
        assert_eq!(encoded_v6[2] & 0x01, 0x01);
        assert_eq!(encoded_v6[2] & 0x7E, 0x00);
        assert_eq!(encoded_v6[3], 0x4C);
    }

    #[test]
    fn group_decode_reject_empty_data(){
        assert!(matches!(GroupAddress::decode(&[]), Err(DecodeError::IncompletePacket)));
    }

    #[test]
    fn group_ipv4_decode_reject_wrong_encoding(){
        let data: [u8; 8] = [1, 1, 0, 0, 192, 168, 1, 1];
        assert!(matches!(GroupAddress::decode(&data), Err(DecodeError::InvalidEncoding(1))));
    }

    #[test]
    fn group_decode_reject_invalid_family(){
        let data: [u8; 8] = [0, 0, 0, 0, 192, 168, 1, 1]; 
        assert!(matches!(GroupAddress::decode(&data), Err(DecodeError::InvalidAddressFamily(0))));
    }

    #[test]
    fn group_ipv4_decode_reject_short_value(){
        let data: [u8; 4] = [1, 0, 0, 0]; 
        assert!(matches!(GroupAddress::decode(&data), Err(DecodeError::IncompletePacket)));
    }

    #[test]
    fn group_ipv4_decode_reports_correct_address_lenght_and_ignores_trailing_bytes(){
        let mut data = vec![1, 0, 0, 0, 192, 168, 1, 1];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // extra trailing bytes

        let (decoded, consumed) = GroupAddress::decode(&data).unwrap();
        assert_eq!(consumed, 8); 
        assert_eq!(decoded.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn group_ipv6_decode_reports_correct_consumed_and_ignores_trailing_bytes() {
        let mut data = vec![2, 0, 0, 0]; // family=IPv6, encoding=0
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()); // 16 bytes
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // trailing junk

        let (decoded, consumed) = GroupAddress::decode(&data).unwrap();
        assert_eq!(consumed, 20);
        assert_eq!(decoded.addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn group_ipv6_decode_rejects_short_address() {
        let data = [2, 0, 0, 0];
        assert!(matches!(GroupAddress::decode(&data), Err(DecodeError::IncompletePacket)));
    }
    // ---- Source address ----
    #[test]
    fn soure_ipv4_roundtrip() {
        let original = SourceAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A,  
        };
        let encoded = original.encode();
        let (decoded, consumed) = SourceAddress::decode(&encoded).unwrap();

        assert_eq!(decoded.addr, original.addr);
        assert_eq!(consumed, encoded.len()); // 1 family + 1 encoding type + 4 address bytes
    }

    #[test]
    fn soure_ipv6_roundtrip(){
        let original = SourceAddress {
            addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A,  
        };
        let encoded = original.encode();
        let (decoded, consumed) = SourceAddress::decode(&encoded).unwrap();

        assert_eq!(decoded.addr, original.addr);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn source_ipv4_encoded_bytes(){
        let original_v4 = SourceAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A, 
        };
        let encoded_v4 = original_v4.encode();
        assert_eq!(encoded_v4[0], 0x01);
        assert_eq!(encoded_v4[1], 0x00);
        assert_eq!(encoded_v4[2] & 0x04, 0x00);
        assert_eq!(encoded_v4[2] & 0x02, 0x02);
        assert_eq!(encoded_v4[2] & 0x01, 0x01);
        assert_eq!(encoded_v4[2] & 0xF8, 0x00);
        assert_eq!(encoded_v4[3], 0x5A);
    }

    #[test]
    fn source_ipv6_encoded_bytes(){
        let original_v6 = SourceAddress {
            addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A,   
        };
        let encoded_v6 = original_v6.encode();
        assert_eq!(encoded_v6[0], 0x02);
        assert_eq!(encoded_v6[1], 0x00);
        assert_eq!(encoded_v6[2] & 0x04, 0x00);
        assert_eq!(encoded_v6[2] & 0x02, 0x02);
        assert_eq!(encoded_v6[2] & 0x01, 0x01);
        assert_eq!(encoded_v6[2] & 0xF8, 0x00);
        assert_eq!(encoded_v6[3], 0x5A);
    }

    #[test]
    fn source_decode_reject_empty_data(){
        assert!(matches!(SourceAddress::decode(&[]), Err(DecodeError::IncompletePacket)));
    }

    #[test]
    fn source_ipv4_decode_reject_wrong_encoding(){
        let data: [u8; 8] = [1, 1, 0, 0, 192, 168, 1, 1];
        assert!(matches!(SourceAddress::decode(&data), Err(DecodeError::InvalidEncoding(1))));
    }

    #[test]
    fn source_decode_reject_invalid_family(){
        let data: [u8; 8] = [0, 0, 0, 0, 192, 168, 1, 1]; 
        assert!(matches!(SourceAddress::decode(&data), Err(DecodeError::InvalidAddressFamily(0))));
    }

    #[test]
    fn source_ipv4_decode_reject_short_value(){
        let data: [u8; 4] = [1, 0, 0, 0]; 
        assert!(matches!(SourceAddress::decode(&data), Err(DecodeError::IncompletePacket)));
    }

    #[test]
    fn source_ipv4_decode_reports_correct_address_lenght_and_ignores_trailing_bytes(){
        let mut data = vec![1, 0, 0, 0, 192, 168, 1, 1];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // extra trailing bytes

        let (decoded, consumed) = SourceAddress::decode(&data).unwrap();
        assert_eq!(consumed, 8); 
        assert_eq!(decoded.addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn source_ipv6_decode_reports_correct_consumed_and_ignores_trailing_bytes() {
        let mut data = vec![2, 0, 0, 0]; // family=IPv6, encoding=0
        data.extend_from_slice(&Ipv6Addr::LOCALHOST.octets()); // 16 bytes
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // trailing junk

        let (decoded, consumed) = SourceAddress::decode(&data).unwrap();
        assert_eq!(consumed, 20);
        assert_eq!(decoded.addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn source_ipv6_decode_rejects_short_address() {
        let data = [2, 0, 0, 0];
        assert!(matches!(SourceAddress::decode(&data), Err(DecodeError::IncompletePacket)));
    }
}

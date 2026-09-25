// This manages the encoding and decoding of PIM packets as described in section 4.9 of RFC 7761
use bytes::{BufMut, BytesMut};
use crate::checksum;
use crate::errors::DecodeError; 
use crate::{packet::{assert::AssertMsg, 
    bootstrap::BootstrapMsg, 
    hello::HelloMsg, 
    join_prune::JoinPruneMsg, 
    register::RegisterMsg, 
    register_stop::RegisterStopMsg, 
    candidate_rp_advertisement::CandidateRpAdvertisementMsg}};

// Different message types
mod assert;
mod hello;
mod register;
mod register_stop;
mod join_prune;
mod bootstrap;
mod candidate_rp_advertisement;

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


// Tests I want to do : 
//  - Correct identification of the type 
//  - Correct encode/decode of header 
//  - IPV6 checks as per rfc 2460, not done yet 
#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::{address::{GroupAddress, SourceAddress, UnicastAddress}, packet::join_prune::MulticastGroup};
    use std::net::{IpAddr, Ipv4Addr};
    use super::*;

    #[test]
    fn pim_type_identification() {
        assert_eq!(PimType::try_from(0).unwrap(), PimType::Hello);
        assert_eq!(PimType::try_from(1).unwrap(), PimType::Register);
        assert_eq!(PimType::try_from(2).unwrap(), PimType::RegisterStop);
        assert_eq!(PimType::try_from(3).unwrap(), PimType::JoinPrune);
        assert_eq!(PimType::try_from(4).unwrap(), PimType::Bootstrap);
        assert_eq!(PimType::try_from(5).unwrap(), PimType::Assert);
        assert_eq!(PimType::try_from(6).unwrap(), PimType::Graft);
        assert_eq!(PimType::try_from(7).unwrap(), PimType::GraftAck);
        assert_eq!(PimType::try_from(8).unwrap(), PimType::CandidateRpAdvertisement);
    }

    #[test]
    fn pim_type_reject_invalid_type() {
        assert!(matches!(PimType::try_from(9), Err(DecodeError::InvalidMessageType(9))))
    }

    // Message tests

    #[test]
    fn short_message_rejected(){
        assert!(matches!(Message::decode(&[0x20, 0x00]), Err(DecodeError::IncompletePacket)))
    } 
    
    #[test]
    fn wrong_version_rejected(){
        assert!(matches!(Message::decode(&[0x11, 0x00, 0x12, 0x12]), Err(DecodeError::InvalidVersion(0x01))))
    }

    #[test]
    fn wrong_type_rejected(){
        assert!(matches!(Message::decode(&[0x29, 0x00, 0x12, 0x12]), Err(DecodeError::InvalidMessageType(0x09))))
    }

    #[test]
    fn reserved_not_zeroed(){
        assert!(matches!(Message::decode(&[0x21, 0x12, 0x4c, 0x21]), Err(DecodeError::InvalidReserved(0x12))))
    }

    // Roundtrips

    #[test]
    fn hello_roundtrip(){
        let original = Message::Hello(HelloMsg { options: vec![] });
        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(matches!(decoded, Message::Hello(_)));
    }

    #[test]
    fn register_simple_roundtrip(){
        let mut packet_bytes = BytesMut::new();
        packet_bytes.put_u16(42);
        let packet = packet_bytes.freeze();
        let original = Message::Register(RegisterMsg { border_bit: false, null_bit: true, packet: packet });
        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(matches!(decoded, Message::Register(RegisterMsg { border_bit: false, null_bit: true, packet: _packet })));
    }

    #[test]
    fn register_padded_roundtrip(){
        let mut packet_bytes = BytesMut::new();
        packet_bytes.put_u8(42);
        let packet = packet_bytes.freeze();
        let original = Message::Register(RegisterMsg { border_bit: false, null_bit: true, packet: packet });
        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(matches!(decoded, Message::Register(RegisterMsg { border_bit: false, null_bit: true, packet: _packet })));
    }

    #[test]
    fn register_empty_roundtrip(){
        let packet = Bytes::new();
        let original = Message::Register(RegisterMsg { border_bit: false, null_bit: true, packet: packet });
        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(matches!(decoded, Message::Register(RegisterMsg { border_bit: false, null_bit: true, packet: _packet })));
    }

    #[test]
    fn register_stop_roundtrip(){
        let correct_grp_addr = GroupAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        };
        let correct_src_addr = UnicastAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        let original = Message::RegisterStop(RegisterStopMsg { 
            group_address: correct_grp_addr , 
            source_address: correct_src_addr
        });
        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert!(matches!(decoded, Message::RegisterStop(RegisterStopMsg { 
            group_address: _correct_grp_addr , 
            source_address: _correct_src_addr
        })));
    }

    #[test]
    fn join_prune_roundtrip(){
        let mut joined_srcs = Vec::new();
        joined_srcs.push(SourceAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A,  
        });
        joined_srcs.push(SourceAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A,  
        });

        let mut pruned_srcs = Vec::new();
        pruned_srcs.push(SourceAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
            s_bit: false,
            w_bit: true,
            r_bit: true,
            mask_byte: 0x5A,  
        });

        let multicast_grp_a = MulticastGroup {
            multicast_group_addr: GroupAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        }, 
        num_joined_sources: 2 as u16, 
        num_pruned_sources: 1 as u16,
        joined_sources: joined_srcs.clone(),
        pruned_sources: pruned_srcs.clone()
        };

        let multicast_grp_b = MulticastGroup {
            multicast_group_addr: GroupAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        }, 
        num_joined_sources: 2 as u16, 
        num_pruned_sources: 1 as u16,
        joined_sources: joined_srcs,
        pruned_sources: pruned_srcs
        };

        let upstream_neighbor_addr = UnicastAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        let mut groups = Vec::new();
        groups.push(multicast_grp_a);
        groups.push(multicast_grp_b); 
        let join_prune_message = Message::JoinPrune(JoinPruneMsg {
            upstream_neighbor_addr,
            num_groups: 2, 
            holdtime: 4, 
            groups 
        });

        let encoded = join_prune_message.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(matches!(decoded, Message::JoinPrune(JoinPruneMsg {
            upstream_neighbor_addr: _upstream_neighbor_addr,
            num_groups: 2, 
            holdtime: 4, 
            groups: _groups 
        })));

    }

    #[test]
    fn assert_roundtrip(){
        let grp_addr = GroupAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            b_bit: false,
            z_bit: true,
            mask_byte: 0x4C, 
        };
        let src_addr = UnicastAddress {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };
        let rp_bit= true;
        let metric_pref = 255 as u32;
        let metric = 255 as u32;
        let original = Message::Assert(AssertMsg { 
            group_address: grp_addr, 
            source_address: src_addr, 
            rp_bit, 
            metric_preference: metric_pref, 
            metric }
        );
        let encoded = original.encode();
        let decoded = Message::decode(&encoded).unwrap();

        assert!(matches!(decoded, _original));
        
    }
}

// thread 'packet::tests::join_prune_roundtrip' (1225524) panicked at holo-pim/src/packet.rs:351:49:
// called `Result::unwrap()` on an `Err` value: InvalidReserved(3)
// TODO:
//  - IPV6 checks as per rfc 2460

use std::net::{IpAddr, Ipv4Addr};
use bytes::{Bytes, BufMut, BytesMut};
use holo_pim::address::{GroupAddress, SourceAddress, UnicastAddress};
use holo_pim::packet::{PimType, Message, HelloMsg, RegisterMsg, RegisterStopMsg, JoinPruneMsg, AssertMsg, MulticastGroup};
use holo_pim::errors::DecodeError;

/* Message type identification tests */
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

/* Message tests */
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

/* Roundtrips */
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

// I got this at some point, cannot seem to reproduce it ...
// thread 'packet::tests::join_prune_roundtrip' (1225524) panicked at holo-pim/src/packet.rs:351:49:
// called `Result::unwrap()` on an `Err` value: InvalidReserved(3)
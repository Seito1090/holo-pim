use crate::{errors::DecodeError, address::{UnicastAddress, GroupAddress, SourceAddress}};
use bytes::{BufMut, BytesMut};

#[derive(Debug)]
pub struct JoinPruneMsg {
    pub upstream_neighbor_addr: UnicastAddress,
    pub num_groups: u8,
    pub holdtime: u16,
    pub groups: Vec<MulticastGroup>,
}

impl JoinPruneMsg {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&self.upstream_neighbor_addr.encode());
        buf.put_u8(0);
        buf.put_u8(self.num_groups);
        buf.put_u16(self.holdtime);
        for grp in &self.groups {
            buf.put(grp.encode());
        }
        buf
    }
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let (upstream_neighbor_addr, neighbor_addr_len) = UnicastAddress::decode(data)?;
        let mut rest = &data[neighbor_addr_len..];
        let num_groups_bytes = u16::from_be_bytes(rest[0..2].try_into().unwrap());

        // Reserved check
        if 0 != (num_groups_bytes & 0xFF00){
            return Err(DecodeError::InvalidReserved((num_groups_bytes >> 8) as u8))
        }

        let num_groups = num_groups_bytes as u8;
        let holdtime = u16::from_be_bytes(rest[2..4].try_into().unwrap());
        rest = &rest[4..];

        let mut groups = Vec::new();

        let mut offset = 0;
        for _grp_idx in 0..num_groups {
            let (gpr, grp_len) = MulticastGroup::decode(&rest[offset..])?;
            groups.push(gpr);
            offset += grp_len;
        }

        Ok(JoinPruneMsg { 
            upstream_neighbor_addr, 
            num_groups, 
            holdtime, 
            groups
        })
    }
}

#[derive(Debug)]
pub struct MulticastGroup {
    pub multicast_group_addr: GroupAddress,
    pub num_joined_sources: u16,
    pub num_pruned_sources: u16,
    pub joined_sources: Vec<SourceAddress>,
    pub pruned_sources: Vec<SourceAddress>,
}

impl MulticastGroup {
    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&self.multicast_group_addr.encode());
        buf.put_u16(self.num_joined_sources);
        buf.put_u16(self.num_pruned_sources);
        for src in &self.joined_sources{
            buf.put(src.encode());
        }
        for prune in &self.pruned_sources{
            buf.put(prune.encode());
        }
        buf
    }
    pub fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut len: usize = 0;
        let (multicast_group_addr, addr_len) = GroupAddress::decode(data)?;
        let num_joined_sources = u16::from_be_bytes(data[addr_len..addr_len+2].try_into().unwrap());
        let num_pruned_sources = u16::from_be_bytes(data[addr_len+2..addr_len+4].try_into().unwrap());
        len += addr_len + 4;
        let mut reste = &data[len..];
        let mut joined_sources: Vec<SourceAddress> = Vec::new();
        for _ in 0..num_joined_sources {
            let (joined_addr, joined_addr_len) = SourceAddress::decode(reste)?;
            joined_sources.push(joined_addr);
            len += joined_addr_len;
            reste = &reste[joined_addr_len..]; 
        } 
        let mut pruned_sources: Vec<SourceAddress> = Vec::new();
        for _ in 0..num_pruned_sources {
            let (pruned_addr, pruned_addr_len) = SourceAddress::decode(reste)?;
            pruned_sources.push(pruned_addr);
            len += pruned_addr_len;
            reste = &reste[pruned_addr_len..];
        }
        Ok((MulticastGroup { 
            multicast_group_addr, 
            num_joined_sources, 
            num_pruned_sources, 
            joined_sources, 
            pruned_sources
        }, len))
    }
}
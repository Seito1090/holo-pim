// This file implements the major states for PIM as explained in RFC7761
use std::{collections::HashMap, net::IpAddr};
use crate::state::{ join_prune::{JoinPruneState, JoinPruneRptState},
                    assert_win::AssertWinState,
                    neighbor::Neighbor, 
                    register::RegisterState};

mod assert_win;
mod join_prune; 
mod neighbor;
mod register;

// NOTE, different timers to be checked in their respective sections, 

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IfIndex(pub u32);

pub struct GeneralState {
    // RFC 7761 section 4.1.1
    // Interface specific
    pub effective_override_interval: u32,
    pub effective_propagation_delay: u32,
    pub suppression_state: SuppressionState, 
    pub neighbor_states: HashMap<IpAddr,Neighbor>,
    pub designated_router_addr: Option<IpAddr>, // does not need to be populated
    pub dr_priority: u32,
}

pub struct StarGState {
    // RFC 7761 section 4.1.2
    // Interface specific
    pub intereface_state: HashMap<IfIndex, InterfaceState>,

    // Not interface specific
    pub upstream_join_prune_state: UpstreamJoinPruneState, 
    pub upstream_join_prune_timer: u16,
    pub last_rp_used: IpAddr,
    pub last_rpf_neighbor_to_rp_used: IpAddr,
}

pub struct SgState {
    // RFC 7761 section 4.1.3 

    // Interface specific
    pub intereface_state: HashMap<IfIndex, InterfaceState>,

    // Not interface specific
    pub upstream_join_prune_state: UpstreamJoinPruneState, 
    pub upstream_join_prune_timer: u16,
    pub last_source_used: IpAddr,
    pub spt_bit: bool,
    pub kat: u16,

    // Additional (S,G) state at the DR
    pub register_state: Option<RegisterState>,
}

pub struct SgRptState {
    // RFC 7761 section 4.1.4

    // Interface specific 
    pub intereface_state: HashMap<IfIndex,RptInterfaceState>,

    // Not interface specific
    pub upstream_state: UpstreamState, 
}

pub struct InterfaceState {
    // Shared part for section 4.1.2 and 4.1.3
    pub local_membership: LocalMembershipState, 
    pub pim_join_prune: JoinPruneState, 
    pub assert_win: AssertWinState,
}

pub struct RptInterfaceState {
    pub local_membership: LocalSgRptState,
    pub pim_join_prune_rpt: JoinPruneRptState,
}

#[derive(Debug)]
pub struct UpstreamState {
    pub state: UpstreamFSMState,
    pub override_timer: u16,
}

#[derive(Debug)]
pub enum SuppressionState { 
    Disable, 
    Enable 
}

#[derive(Debug, PartialEq)]
pub enum LocalMembershipState {
    NoInfo, 
    Include,
}

#[derive(Debug)]
pub enum UpstreamJoinPruneState {
    NotJoined,
    Joined,
}

#[derive(Debug)]
pub enum LocalSgRptState {
    NoInfo,
    Exclude,
}

#[derive(Debug)]
pub enum UpstreamFSMState {
    RPTNotJoined, 
    NotPruned,
    Pruned,
}

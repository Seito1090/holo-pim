use std::{collections::HashMap, net::IpAddr};
use crate::state::{ join_prune_state::JoinPruneState, 
                    assert_win_state::AssertWinState,
                    neighbor_state::Neighbor};

// This file implements the major states for PIM as explained in RFC7761
mod assert_win_state;
mod join_prune_state; 
mod neighbor_state;

pub struct GeneralState {
    // RFC 7761 section 4.1.1
    // Interface specific
    pub effective_override_interval: u32,
    pub effective_propagation_delay: u32,
    pub suppression_state: bool, // disable : 0, enable : 1 
    pub neighbor_states: HashMap<IpAddr,Neighbor>,
    pub designated_router_addr: Option<IpAddr>, // does not need to be populated
    pub dr_priority: u32,
}

pub struct SGStState {
    // RFC 7761 section 4.1.2
    // Interface specific
    pub local_membership_state: bool, // no info : 0, include : 1
    pub pim_join_prune_state: HashMap<IpAddr, JoinPruneState>,
    pub pim_assert_win_state: HashMap<IpAddr, AssertWinState>,

    // Not interface specific
    pub upstream_join_prune_state: bool, // not joined: 0, joined: 1
    pub upstream_join_prune_timer: u16,
    pub last_rp_used: IpAddr,
    pub last_rpf_neighbor_to_rp_used: IpAddr,
}

pub struct SGState {
    // RFC 7761 section 4.1.3 and 4.1.4
    // Interface specific
    pub local_membership_state: bool, // no info : 0, include : 1
    pub pim_join_prune_state: HashMap<IpAddr, JoinPruneState>,
    pub pim_assert_win_state: HashMap<IpAddr, AssertWinState>, // not necessary for 4.1.4

    // Not interface specific 4.1.3
    pub upstream_join_prune_state: bool, // not joined: 0, joined: 1
    pub upstream_join_prune_timer: u16,
    pub last_rp_used: IpAddr,
    pub last_rpf_neighbor_to_rp_used: IpAddr,
    pub spt_bit: bool,
    pub keep_alive_timer: u16,

    // Not interface specific 4.1.4
    pub upstream_state: u8, 
    pub override_timer: u16,
}


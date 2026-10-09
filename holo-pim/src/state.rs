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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ join_prune::{JoinPruneState, JoinPruneRptState, JoinPruneRptFSMState},
                    assert_win::{AssertWinState, AssertWinFSMState},
                    register::{RegisterState, RegisterFSMState} };
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_ipv4(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    // ---- IfIndex sanity ----

    #[test]
    fn ifindex_usable_as_hashmap_key() {
        let mut map: HashMap<IfIndex, u32> = HashMap::new();
        map.insert(IfIndex(1), 100);
        map.insert(IfIndex(2), 200);
        assert_eq!(map.get(&IfIndex(1)), Some(&100));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn ifindex_equality_and_ordering() {
        assert_eq!(IfIndex(1), IfIndex(1));
        assert_ne!(IfIndex(1), IfIndex(2));
        assert!(IfIndex(1) < IfIndex(2));
    }

    // ---- GeneralState ----

    #[test]
    fn general_state_constructs_with_empty_neighbors() {
        let state = GeneralState {
            effective_override_interval: 3000,
            effective_propagation_delay: 500,
            suppression_state: SuppressionState::Enable,
            neighbor_states: HashMap::new(),
            designated_router_addr: None,
            dr_priority: 1,
        };
        assert!(state.neighbor_states.is_empty());
        assert!(state.designated_router_addr.is_none());
    }

    // ---- StarGState ----

    fn sample_interface_state() -> InterfaceState {
        InterfaceState {
            local_membership: LocalMembershipState::Include,
            pim_join_prune: JoinPruneState {
                state: join_prune::JoinPruneFSMState::NoInfo,
                ppt: 0,
                et: 0,
            },
            assert_win: AssertWinState { 
                state: AssertWinFSMState::NoInfo, 
                at: 1, 
                assert_winner: sample_ipv4(1), 
                assert_winner_metric: "HELLO".to_string(),
            },
        }
    }

    #[test]
    fn star_g_state_constructs_and_tracks_one_interface() {
        let mut interface_state = HashMap::new();
        interface_state.insert(IfIndex(1), sample_interface_state());

        let state = StarGState {
            intereface_state: interface_state,
            upstream_join_prune_state: UpstreamJoinPruneState::Joined,
            upstream_join_prune_timer: 60,
            last_rp_used: sample_ipv4(1),
            last_rpf_neighbor_to_rp_used: sample_ipv4(2),
        };

        assert_eq!(state.intereface_state.len(), 1);
        assert_eq!(
            state.intereface_state.get(&IfIndex(1)).unwrap().local_membership,
            LocalMembershipState::Include
        );
    }

    #[test]
    fn star_g_state_no_interfaces_is_valid() {
        let state = StarGState {
            intereface_state: HashMap::new(),
            upstream_join_prune_state: UpstreamJoinPruneState::NotJoined,
            upstream_join_prune_timer: 0,
            last_rp_used: sample_ipv4(1),
            last_rpf_neighbor_to_rp_used: sample_ipv4(1),
        };
        assert!(state.intereface_state.is_empty());
    }

    // ---- SgState ----

    #[test]
    fn sg_state_constructs_without_register_state_when_not_dr() {
        let state = SgState {
            intereface_state: HashMap::new(),
            upstream_join_prune_state: UpstreamJoinPruneState::NotJoined,
            upstream_join_prune_timer: 0,
            last_source_used: sample_ipv4(3),
            spt_bit: false,
            kat: 0,
            register_state: None,
        };
        assert!(state.register_state.is_none());
    }

    #[test]
    fn sg_state_constructs_with_register_state_when_dr() {
        let state = SgState {
            intereface_state: HashMap::new(),
            upstream_join_prune_state: UpstreamJoinPruneState::Joined,
            upstream_join_prune_timer: 60,
            last_source_used: sample_ipv4(3),
            spt_bit: true,
            kat: 210,
            register_state: Some(RegisterState {
                state: RegisterFSMState::Join, 
                rst: 0,
            }),
        };
        assert!(state.register_state.is_some());
        assert!(state.spt_bit);
    }

    // ---- SgRptState ----

    #[test]
    fn sg_rpt_state_tracks_per_interface_prune_state() {
        let mut intereface_state = HashMap::new();
        intereface_state.insert(
            IfIndex(1),
            RptInterfaceState { 
                local_membership: LocalSgRptState::Exclude,
                pim_join_prune_rpt: JoinPruneRptState {
                    state: JoinPruneRptFSMState::NoInfo,
                    ppt: 1,
                    et: 2,
                },
            },
        );

        let state = SgRptState {
            intereface_state,
            upstream_state: UpstreamState {
                state: UpstreamFSMState::NotPruned,
                override_timer: 3,
            },
        };

        assert_eq!(state.intereface_state.len(), 1);
    }
}
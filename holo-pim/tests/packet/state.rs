/*  Tests for routing state structures used by the PIM implementation. */
use std::{collections::HashMap, net::{IpAddr, Ipv4Addr}};
use holo_pim::state::*;

fn sample_ipv4(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
}

// ---- IfIndex sanity ----

#[test]
fn ifindex_usable_as_hashmap_key() {
    let mut map: HashMap<InterfaceIndex, u32> = HashMap::new();
    map.insert(InterfaceIndex(1), 100);
    map.insert(InterfaceIndex(2), 200);
    assert_eq!(map.get(&InterfaceIndex(1)), Some(&100));
    assert_eq!(map.len(), 2);
}

#[test]
fn ifindex_equality_and_ordering() {
    assert_eq!(InterfaceIndex(1), InterfaceIndex(1));
    assert_ne!(InterfaceIndex(1), InterfaceIndex(2));
    assert!(InterfaceIndex(1) < InterfaceIndex(2));
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
            state: JoinPruneFSMState::NoInfo,
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
    interface_state.insert(InterfaceIndex(1), sample_interface_state());

    let state = StarGroupState {
        intereface_state: interface_state,
        upstream_join_prune_state: UpstreamJoinPruneState::Joined,
        upstream_join_prune_timer: 60,
        last_rp_used: sample_ipv4(1),
        last_rpf_neighbor_to_rp_used: sample_ipv4(2),
    };

    assert_eq!(state.intereface_state.len(), 1);
    assert_eq!(
        state.intereface_state.get(&InterfaceIndex(1)).unwrap().local_membership,
        LocalMembershipState::Include
    );
}

#[test]
fn star_g_state_no_interfaces_is_valid() {
    let state = StarGroupState {
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
    let state = SourceGroupState {
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
    let state = SourceGroupState {
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

// ---- SourceGroupRptState ----

#[test]
fn sg_rpt_state_tracks_per_interface_prune_state() {
    let mut intereface_state = HashMap::new();
    intereface_state.insert(
        InterfaceIndex(1),
        RptInterfaceState { 
            local_membership: LocalSgRptState::Exclude,
            pim_join_prune_rpt: JoinPruneRptState {
                state: JoinPruneRptFSMState::NoInfo,
                ppt: 1,
                et: 2,
            },
        },
    );

    let state = SourceGroupRptState {
        intereface_state,
        upstream_state: UpstreamState {
            state: UpstreamFSMState::NotPruned,
            override_timer: 3,
        },
    };

    assert_eq!(state.intereface_state.len(), 1);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinPruneState {
    pub state: JoinPruneFSMState, 
    pub ppt: u16, // prune-pending timer 
    pub et: u16,  // join prune expiry timer 
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPruneFSMState {
    NoInfo,
    Join,
    PrunePending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinPruneRptState {
    pub state: JoinPruneRptFSMState, 
    pub ppt: u16, // prune-pending timer 
    pub et: u16,  // join prune expiry timer 
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinPruneRptFSMState {
    NoInfo,
    Pruned, 
    PrunePending,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterState {
    pub state: RegisterFSMState, 
    pub rst: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterFSMState {
    Join, 
    Prune, 
    JoinPending,
    NoInfo,
}
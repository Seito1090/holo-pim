use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertWinState {
    pub state: AssertWinFSMState,
    pub at: u16, // Assert timer
    pub assert_winner: IpAddr,
    pub assert_winner_metric: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertWinFSMState {
    NoInfo, 
    ILostAssert,
    IWonAssert,
}
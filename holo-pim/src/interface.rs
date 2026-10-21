use std::net::Ipv4Addr;
use std::sync::Arc;

use holo_utils::bytes::Bytes;
use holo_utils::socket::{AsyncFd, Socket};
use holo_utils::southbound::InterfaceFlags;
use holo_utils::task::Task;
use tokio::sync::mpsc::{self, Sender, UnboundedSender};

use crate::instance::ProtocolInputMsg;
use crate::network;

#[derive(Debug)]
pub struct Interface {
    pub name: String,
    pub flags: InterfaceFlags,
    pub ifindex: Option<u32>,
    pub active: bool,
    pub net: Option<InterfaceNet>,
}

#[derive(Debug)]
pub struct InterfaceNet {
    pub tx: UnboundedSender<(Ipv4Addr, Bytes)>,
    _rx_socket: Arc<AsyncFd<Socket>>,
    _rx_task: Task<()>,
    _tx_task: Task<()>,
}

impl Interface {
    pub fn new(name: String) -> Self {
        Self {
            name,
            flags: InterfaceFlags::default(),
            ifindex: None,
            active: false,
            net: None,
        }
    }

    pub fn update(
        &mut self,
        input_tx: &Sender<ProtocolInputMsg>,
    ) -> Result<(), std::io::Error> {
        let Some(ifindex) = self.ifindex else {
            return Ok(());
        };
        if !self.flags.contains(InterfaceFlags::OPERATIVE) {
            self.stop();
            return Ok(());
        }
        if self.active {
            return Ok(());
        }

        let rx_socket = Arc::new(AsyncFd::new(network::socket_rx()?)?);
        network::join_multicast(rx_socket.get_ref(), ifindex)?;
        let rx_task = network::net_rx(rx_socket.clone(), input_tx.clone());
        let tx_socket = Arc::new(AsyncFd::new(network::socket_tx(&self.name)?)?);
        let (tx, tx_rx) = mpsc::unbounded_channel();
        let tx_task_socket = tx_socket.clone();
        let tx_task =
            Task::spawn(async move { network::net_tx(tx_task_socket, tx_rx).await });

        self.net = Some(InterfaceNet {
            tx,
            _rx_socket: rx_socket,
            _rx_task: rx_task,
            _tx_task: tx_task,
        });
        self.active = true;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.active = false;
        self.net = None;
    }
}

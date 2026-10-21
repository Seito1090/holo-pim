use std::net::{Ipv4Addr, Ipv6Addr};
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
    pub tx_v4: Option<UnboundedSender<(Ipv4Addr, Bytes)>>,
    pub tx_v6: Option<UnboundedSender<(Ipv6Addr, Bytes)>>,
    _rx_tasks: Vec<Task<()>>,
    _rx_sockets: Vec<Arc<AsyncFd<Socket>>>,
    _tx_tasks: Vec<Task<()>>,
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
        ipv4: bool,
        ipv6: bool,
    ) -> Result<(), std::io::Error> {
        let Some(ifindex) = self.ifindex else {
            return Ok(());
        };
        if !self.flags.contains(InterfaceFlags::OPERATIVE) || (!ipv4 && !ipv6) {
            self.stop();
            return Ok(());
        }
        if self.active {
            return Ok(());
        }

        let mut rx_tasks = Vec::new();
        let mut rx_sockets = Vec::new();
        let mut tx_tasks = Vec::new();
        let mut tx_v4 = None;
        let mut tx_v6 = None;
        if ipv4 {
            let rx = Arc::new(AsyncFd::new(network::socket_rx_v4()?)?);
            network::join_multicast_v4(rx.get_ref(), ifindex)?;
            rx_tasks.push(network::net_rx_v4(rx.clone(), input_tx.clone()));
            rx_sockets.push(rx);
            let tx_socket =
                Arc::new(AsyncFd::new(network::socket_tx_v4(&self.name)?)?);
            let (tx, rx) = mpsc::unbounded_channel();
            let task_socket = tx_socket.clone();
            tx_tasks.push(Task::spawn(async move {
                network::net_tx_v4(task_socket, rx).await
            }));
            tx_v4 = Some(tx);
        }
        if ipv6 {
            let rx = Arc::new(AsyncFd::new(network::socket_rx_v6()?)?);
            network::join_multicast_v6(rx.get_ref(), ifindex)?;
            rx_tasks.push(network::net_rx_v6(rx.clone(), input_tx.clone()));
            rx_sockets.push(rx);
            let tx_socket =
                Arc::new(AsyncFd::new(network::socket_tx_v6(&self.name)?)?);
            let (tx, rx) = mpsc::unbounded_channel();
            let task_socket = tx_socket.clone();
            tx_tasks.push(Task::spawn(async move {
                network::net_tx_v6(task_socket, ifindex, rx).await
            }));
            tx_v6 = Some(tx);
        }
        self.net = Some(InterfaceNet {
            tx_v4,
            tx_v6,
            _rx_tasks: rx_tasks,
            _rx_sockets: rx_sockets,
            _tx_tasks: tx_tasks,
        });
        self.active = true;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.active = false;
        self.net = None;
    }
}

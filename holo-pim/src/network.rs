use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::ops::Deref;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use holo_utils::bytes::Bytes;
use holo_utils::capabilities;
use holo_utils::socket::{AsyncFd, RawSocketExt, Socket, SocketExt};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};

use crate::instance::ProtocolInputMsg;

pub const PIM_IP_PROTO: i32 = 103;
pub const ALL_PIM_ROUTERS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 13);

pub fn socket_rx() -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use socket2::{Domain, Protocol, Type};
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(PIM_IP_PROTO)),
            )
        })?;
        socket.set_nonblocking(true)?;
        socket.set_ipv4_pktinfo(true)?;
        socket.set_mrt_init(true)?;
        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        Ok(Socket {})
    }
}

pub fn socket_tx(ifname: &str) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use socket2::{Domain, Protocol, Type};
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV4,
                Type::RAW,
                Some(Protocol::from(PIM_IP_PROTO)),
            )
        })?;
        capabilities::raise(|| socket.bind_device(Some(ifname.as_bytes())))?;
        socket.set_nonblocking(true)?;
        socket.set_multicast_loop_v4(false)?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_ipv4_pktinfo(true)?;
        socket.set_tos_v4(libc::IPTOS_PREC_INTERNETCONTROL.into())?;
        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        let _ = ifname;
        Ok(Socket {})
    }
}

pub fn join_multicast(
    socket: &Socket,
    ifindex: u32,
) -> Result<(), std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        socket.join_multicast_ifindex_v4(&ALL_PIM_ROUTERS_V4, ifindex)
    }
    #[cfg(feature = "testing")]
    {
        let _ = (socket, ifindex);
        Ok(())
    }
}

pub fn net_rx(
    socket: Arc<AsyncFd<Socket>>,
    tx: Sender<ProtocolInputMsg>,
) -> holo_utils::task::Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        holo_utils::task::Task::spawn(async move {
            let mut buf = [0; 16384];
            let mut iov = [IoSliceMut::new(&mut buf)];
            let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);
            loop {
                let packet = {
                    let result = socket
                        .async_io(tokio::io::Interest::READABLE, |socket| {
                            let (src, bytes) = {
                                let msg = nix::sys::socket::recvmsg::<
                                    nix::sys::socket::SockaddrIn,
                                >(
                                    socket.as_raw_fd(),
                                    &mut iov,
                                    Some(&mut cmsgspace),
                                    nix::sys::socket::MsgFlags::empty(),
                                )
                                .map_err(std::io::Error::from)?;
                                (msg.address.map(|addr| addr.ip()), msg.bytes)
                            };
                            let data = if bytes >= 24 {
                                Some(Bytes::copy_from_slice(
                                    &iov[0].deref()[20..bytes],
                                ))
                            } else {
                                None
                            };
                            Ok((src, data))
                        })
                        .await;
                    let Ok(msg) = result else { continue };
                    let (Some(src), Some(data)) = msg else {
                        continue;
                    };
                    Some((src, data))
                };
                if let Some((src, data)) = packet {
                    let _ = tx.send(ProtocolInputMsg::NetRx { src, data }).await;
                }
            }
        })
    }
    #[cfg(feature = "testing")]
    {
        let _ = (socket, tx);
        holo_utils::task::Task::spawn(async { std::future::pending().await })
    }
}

#[allow(unused_mut)]
pub async fn net_tx(
    socket: Arc<AsyncFd<Socket>>,
    mut rx: UnboundedReceiver<(Ipv4Addr, Bytes)>,
) {
    #[cfg(not(feature = "testing"))]
    while let Some((dst, data)) = rx.recv().await {
        let sockaddr = nix::sys::socket::SockaddrIn::from(SocketAddrV4::new(dst, 0));
        let iov = [IoSlice::new(&data)];
        let _ = socket
            .async_io(tokio::io::Interest::WRITABLE, |socket| {
                nix::sys::socket::sendmsg(
                    socket.as_raw_fd(),
                    &iov,
                    &[],
                    nix::sys::socket::MsgFlags::empty(),
                    Some(&sockaddr),
                )
                .map_err(std::io::Error::from)
            })
            .await;
    }
    #[cfg(feature = "testing")]
    {
        let _ = (socket, rx);
        std::future::pending::<()>().await;
    }
}

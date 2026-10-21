use std::io::{IoSlice, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
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
pub const ALL_PIM_ROUTERS_V6: Ipv6Addr =
    Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000d);

pub fn socket_rx_v4() -> Result<Socket, std::io::Error> {
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

pub fn socket_tx_v4(ifname: &str) -> Result<Socket, std::io::Error> {
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

pub fn socket_rx_v6() -> Result<Socket, std::io::Error> {
    socket_v6(None)
}

pub fn socket_tx_v6(ifname: &str) -> Result<Socket, std::io::Error> {
    socket_v6(Some(ifname))
}

fn socket_v6(ifname: Option<&str>) -> Result<Socket, std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        use socket2::{Domain, Protocol, Type};
        let socket = capabilities::raise(|| {
            Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(PIM_IP_PROTO)),
            )
        })?;
        if let Some(ifname) = ifname {
            capabilities::raise(|| {
                socket.bind_device(Some(ifname.as_bytes()))
            })?;
        }
        socket.set_nonblocking(true)?;
        socket.set_multicast_loop_v6(false)?;
        socket.set_ipv6_pktinfo(true)?;
        socket.set_ipv6_checksum(2)?;
        socket.set_ipv6_tclass(libc::IPTOS_PREC_INTERNETCONTROL.into())?;
        Ok(socket)
    }
    #[cfg(feature = "testing")]
    {
        let _ = ifname;
        Ok(Socket {})
    }
}

pub fn join_multicast_v4(
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

pub fn join_multicast_v6(
    socket: &Socket,
    ifindex: u32,
) -> Result<(), std::io::Error> {
    #[cfg(not(feature = "testing"))]
    {
        socket2::SockRef::from(socket)
            .join_multicast_v6(&ALL_PIM_ROUTERS_V6, ifindex)
    }
    #[cfg(feature = "testing")]
    {
        let _ = (socket, ifindex);
        Ok(())
    }
}

pub fn net_rx_v4(
    socket: Arc<AsyncFd<Socket>>,
    tx: Sender<ProtocolInputMsg>,
) -> holo_utils::task::Task<()> {
    net_rx_v4_impl(socket, tx)
}

#[cfg(not(feature = "testing"))]
fn net_rx_v4_impl(
    socket: Arc<AsyncFd<Socket>>,
    tx: Sender<ProtocolInputMsg>,
) -> holo_utils::task::Task<()> {
    holo_utils::task::Task::spawn(async move {
        let mut buf = [0; 16384];
        let mut iov = [IoSliceMut::new(&mut buf)];
        let mut cmsgspace = nix::cmsg_space!(libc::in_pktinfo);
        loop {
            let result = socket.async_io(tokio::io::Interest::READABLE, |socket| {
                let (src, dst, bytes) = {
                    let msg = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrIn>(
                        socket.as_raw_fd(), &mut iov, Some(&mut cmsgspace),
                        nix::sys::socket::MsgFlags::empty(),
                    ).map_err(std::io::Error::from)?;
                    let dst = msg.cmsgs().ok().and_then(|mut cmsgs| {
                        cmsgs.find_map(|cmsg| {
                            if let nix::sys::socket::ControlMessageOwned::Ipv4PacketInfo(pktinfo) = cmsg {
                                Some(Ipv4Addr::from(u32::from_be(pktinfo.ipi_addr.s_addr)))
                            } else { None }
                        })
                    });
                    (msg.address.map(|addr| addr.ip()), dst, msg.bytes)
                };
                let header_len = iov[0].deref().first().map(|byte| (*byte & 0x0f) as usize * 4);
                let data = if let Some(header_len) = header_len.filter(|len| *len >= 20 && *len <= bytes) {
                    Some(Bytes::copy_from_slice(&iov[0].deref()[header_len..bytes]))
                } else { None };
                Ok((src, dst, data))
            }).await;
            let Ok((Some(src), Some(dst), Some(data))) = result else {
                continue;
            };
            let _ = tx
                .send(ProtocolInputMsg::NetRx {
                    src: src.into(),
                    dst: dst.into(),
                    data,
                })
                .await;
        }
    })
}

#[cfg(feature = "testing")]
fn net_rx_v4_impl(
    _socket: Arc<AsyncFd<Socket>>,
    _tx: Sender<ProtocolInputMsg>,
) -> holo_utils::task::Task<()> {
    holo_utils::task::Task::spawn(async { std::future::pending().await })
}

pub fn net_rx_v6(
    socket: Arc<AsyncFd<Socket>>,
    tx: Sender<ProtocolInputMsg>,
) -> holo_utils::task::Task<()> {
    #[cfg(not(feature = "testing"))]
    {
        holo_utils::task::Task::spawn(async move {
            let mut buf = [0; 16384];
            let mut iov = [IoSliceMut::new(&mut buf)];
            let mut cmsgspace = nix::cmsg_space!(libc::in6_pktinfo);
            loop {
                let result = socket.async_io(tokio::io::Interest::READABLE, |socket| {
                    let (src, dst, bytes) = {
                        let msg = nix::sys::socket::recvmsg::<nix::sys::socket::SockaddrIn6>(
                            socket.as_raw_fd(), &mut iov, Some(&mut cmsgspace),
                            nix::sys::socket::MsgFlags::empty(),
                        ).map_err(std::io::Error::from)?;
                        let dst = msg.cmsgs().ok().and_then(|mut cmsgs| {
                            cmsgs.find_map(|cmsg| {
                                if let nix::sys::socket::ControlMessageOwned::Ipv6PacketInfo(pktinfo) = cmsg {
                                    Some(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr))
                                } else { None }
                            })
                        });
                        (msg.address.map(|addr| addr.ip()), dst, msg.bytes)
                    };
                    let data = if bytes >= 4 {
                        Some(Bytes::copy_from_slice(&iov[0].deref()[..bytes]))
                    } else { None };
                    Ok((src, dst, data))
                }).await;
                let Ok((Some(src), Some(dst), Some(data))) = result else {
                    continue;
                };
                let _ = tx
                    .send(ProtocolInputMsg::NetRx {
                        src: src.into(),
                        dst: dst.into(),
                        data,
                    })
                    .await;
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
pub async fn net_tx_v4(
    socket: Arc<AsyncFd<Socket>>,
    mut rx: UnboundedReceiver<(Ipv4Addr, Bytes)>,
) {
    #[cfg(not(feature = "testing"))]
    while let Some((dst, data)) = rx.recv().await {
        let sockaddr =
            nix::sys::socket::SockaddrIn::from(SocketAddrV4::new(dst, 0));
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

#[allow(unused_mut)]
pub async fn net_tx_v6(
    socket: Arc<AsyncFd<Socket>>,
    ifindex: u32,
    mut rx: UnboundedReceiver<(Ipv6Addr, Bytes)>,
) {
    #[cfg(not(feature = "testing"))]
    while let Some((dst, data)) = rx.recv().await {
        let sockaddr = nix::sys::socket::SockaddrIn6::from(SocketAddrV6::new(
            dst, 0, 0, ifindex,
        ));
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
        let _ = (socket, ifindex, rx);
        std::future::pending::<()>().await;
    }
}

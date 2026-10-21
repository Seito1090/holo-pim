use std::collections::BTreeSet;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use holo_northbound::configuration::{
    Provider as ConfigProvider, YangConfigOps,
};
use holo_northbound::rpc;
use holo_northbound::state;
use holo_protocol::{
    InstanceChannelsTx, InstanceShared, MessageReceiver, ProtocolInstance,
};
use holo_utils::ibus::IbusMsg;
use holo_utils::protocol::Protocol;
use holo_utils::southbound::InterfaceUpdateMsg;
use holo_yang::ToYang;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{self, Receiver, Sender};

use crate::northbound::configuration::InstanceCfg;
use crate::interface::Interface;
use crate::northbound::yang_gen::config::{
    self, ConfigChange, InterfaceChange, InterfaceEntryChange,
};

#[derive(Debug, Default)]
pub struct InstanceState;

#[derive(Debug)]
pub struct Instance {
    pub name: String,
    pub config: InstanceCfg,
    pub state: Option<InstanceState>,
    pub interfaces: BTreeMap<String, Interface>,
    pub tx: InstanceChannelsTx<Instance>,
    pub shared: InstanceShared,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProtocolInputMsg {
    NetRx { src: Ipv4Addr, data: holo_utils::bytes::Bytes },
}

#[derive(Debug, Serialize)]
pub enum ProtocolOutputMsg {}

#[derive(Clone, Debug)]
pub struct ProtocolInputChannelsTx {
    pub tx: Sender<ProtocolInputMsg>,
}

#[derive(Debug)]
pub struct ProtocolInputChannelsRx {
    _rx: Receiver<ProtocolInputMsg>,
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Event {
    InstanceUpdate,
}

impl MessageReceiver<ProtocolInputMsg> for ProtocolInputChannelsRx {
    async fn recv(&mut self) -> Option<ProtocolInputMsg> {
        self._rx.recv().await
    }
}

impl ProtocolInstance for Instance {
    const PROTOCOL: Protocol = Protocol::PIM;

    type ProtocolInputMsg = ProtocolInputMsg;
    type ProtocolOutputMsg = ProtocolOutputMsg;
    type ProtocolInputChannelsTx = ProtocolInputChannelsTx;
    type ProtocolInputChannelsRx = ProtocolInputChannelsRx;

    fn new(
        name: String,
        shared: InstanceShared,
        tx: InstanceChannelsTx<Self>,
    ) -> Self {
        Self {
            name,
            config: Default::default(),
            state: None,
            interfaces: BTreeMap::new(),
            tx,
            shared,
        }
    }

    fn init(&mut self) {
        if self.config.enabled
            && (self.config.ipv4.enabled || self.config.ipv6.enabled)
        {
            self.state = Some(InstanceState);
        }
    }

    fn shutdown(mut self) {
        self.state = None;
    }

    fn process_ibus_msg(&mut self, msg: IbusMsg) {
        if let IbusMsg::InterfaceUpd(msg) = msg {
            self.process_interface_update(msg);
        }
    }

    fn process_protocol_msg(&mut self, _msg: ProtocolInputMsg) {}

    fn protocol_input_channels()
    -> (ProtocolInputChannelsTx, ProtocolInputChannelsRx) {
        let (tx, rx) = mpsc::channel(4);
        (
            ProtocolInputChannelsTx { tx },
            ProtocolInputChannelsRx { _rx: rx },
        )
    }

    #[cfg(feature = "testing")]
    fn test_dir() -> String {
        format!("{}/tests", env!("CARGO_MANIFEST_DIR"))
    }
}

impl Instance {
    fn process_interface_update(&mut self, msg: InterfaceUpdateMsg) {
        let Some(iface) = self.interfaces.get_mut(&msg.ifname) else {
            return;
        };
        iface.flags = msg.flags;
        iface.ifindex = Some(msg.ifindex);
        if let Err(error) = iface.update(&self.tx.protocol_input.tx) {
            tracing::error!(interface = %iface.name, %error, "failed to update PIM interface");
        }
    }
}

impl ConfigProvider for Instance {
    type Event = Event;
    type Resource = ();
    type Change = ConfigChange;

    const YANG_OPS_CONFIG: YangConfigOps<ConfigChange> =
        config::YANG_OPS_CONFIG;

    fn apply(
        &mut self,
        change: ConfigChange,
        _resource: &mut Option<Self::Resource>,
        event_queue: &mut BTreeSet<Event>,
    ) -> Result<(), holo_northbound::error::ApplyError> {
        match change {
            ConfigChange::Enabled(value) => self.config.enabled = value,
            ConfigChange::Ipv4Enabled(value) => {
                self.config.ipv4.enabled = value
            }
            ConfigChange::Ipv6Enabled(value) => {
                self.config.ipv6.enabled = value
            }
            ConfigChange::Interface(keys, change) => match change {
                InterfaceChange::Create => {
                    let ifname = keys.name.clone();
                    self.config
                        .interfaces
                        .insert(ifname.clone(), Default::default());
                    self.interfaces
                        .insert(ifname.clone(), Interface::new(ifname.clone()));
                    self.tx.ibus.interface_sub(Some(ifname), None);
                }
                InterfaceChange::Delete => {
                    self.config.interfaces.remove(&keys.name);
                    self.interfaces.remove(&keys.name);
                }
                InterfaceChange::Entry(change) => {
                    let iface = self
                        .config
                        .interfaces
                        .get_mut(&keys.name)
                        .ok_or(
                            holo_northbound::error::ApplyError::EntryNotFound,
                        )?;
                    match change {
                        InterfaceEntryChange::Enabled(value) => {
                            iface.enabled = value
                        }
                        InterfaceEntryChange::DrPriority(value) => {
                            iface.dr_priority = value
                        }
                        InterfaceEntryChange::HelloInterval(value) => {
                            iface.hello_interval = value
                        }
                        InterfaceEntryChange::HelloHoldtime(value) => {
                            iface.hello_holdtime = value
                        }
                        InterfaceEntryChange::PropagationDelay(value) => {
                            iface.propagation_delay = value
                        }
                        InterfaceEntryChange::OverrideInterval(value) => {
                            iface.override_interval = value
                        }
                        InterfaceEntryChange::SuppressionEnabled(value) => {
                            iface.suppression_enabled = value
                        }
                    }
                }
            },
        }
        event_queue.insert(Event::InstanceUpdate);
        Ok(())
    }

    fn process_event(&mut self, _event: Event) {
        let input_tx = self.tx.protocol_input.tx.clone();
        for iface in self.interfaces.values_mut() {
            if let Err(error) = iface.update(&input_tx) {
                tracing::error!(interface = %iface.name, %error, "failed to update PIM interface");
            }
        }
    }
}

impl rpc::Provider for Instance {
    const YANG_OPS: rpc::YangOps<Self> =
        crate::northbound::yang_gen::ops::YANG_OPS_RPC;
}

impl state::Provider for Instance {
    type ListEntry<'a> = crate::northbound::yang_gen::ops::ListEntry<'a>;
    const YANG_OPS: state::YangOps<Self> =
        crate::northbound::yang_gen::ops::YANG_OPS_STATE;

    fn top_level_node(&self) -> String {
        format!(
            "/ietf-routing:routing/control-plane-protocols/control-plane-protocol[type='{}'][name='{}']/holo-pim:pim",
            Protocol::PIM.to_yang(),
            self.name
        )
    }
}

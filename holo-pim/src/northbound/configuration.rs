use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct InstanceCfg {
    pub enabled: bool,
    pub ipv4: InstanceIpv4Cfg,
    pub ipv6: InstanceIpv6Cfg,
    pub interfaces: BTreeMap<String, InterfaceCfg>,
}

#[derive(Debug)]
pub struct InstanceIpv4Cfg {
    pub enabled: bool,
}

#[derive(Debug)]
pub struct InstanceIpv6Cfg {
    pub enabled: bool,
}

#[derive(Debug)]
pub struct InterfaceCfg {
    pub enabled: bool,
    pub dr_priority: u32,
    pub hello_interval: u16,
    pub hello_holdtime: u16,
    pub propagation_delay: u16,
    pub override_interval: u16,
    pub suppression_enabled: bool,
}

impl Default for InstanceIpv4Cfg {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl Default for InstanceIpv6Cfg {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl Default for InterfaceCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            dr_priority: 1,
            hello_interval: 30,
            hello_holdtime: 105,
            propagation_delay: 500,
            override_interval: 2500,
            suppression_enabled: false,
        }
    }
}

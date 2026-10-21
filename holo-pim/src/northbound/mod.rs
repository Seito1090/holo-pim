pub mod configuration;

#[allow(unused_imports, unused_variables)]
pub mod yang_gen {
    pub use routing::control_plane_protocols::control_plane_protocol::pim;

    include!(concat!(env!("OUT_DIR"), "/yang_objects.rs"));
    pub mod config {
        use super::*;
        include!(concat!(env!("OUT_DIR"), "/yang_config.rs"));
    }
}

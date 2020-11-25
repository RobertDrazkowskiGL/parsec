// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Microchip CryptoAuthentication Library provider
//!
//! This provider is a hardware based implementation of PSA Crypto, Mbed Crypto.
use super::Provide;
use derivative::Derivative;
use log::trace;
use std::collections::HashSet;
use uuid::Uuid;

use parsec_interface::operations::list_providers::ProviderInfo;

use parsec_interface::operations::psa_hash_compute;

use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};

//use parsec_interface::operations::psa_algorithm::Hash;

use rust_cryptoauthlib;

mod hash;

const SUPPORTED_OPCODES: [Opcode; 1] = [
    Opcode::PsaHashCompute,
];

/// CryptoAuthLib provider structure
#[derive(Derivative)]
#[derivative(Debug, Copy, Clone)]
pub struct Provider {
    device: rust_cryptoauthlib::AtcaDevice,
}

impl Provider {
    /// Creates and initialise a new instance of CryptoAuthLibProvider
    // TODO - remove "pub" below. Implement ProviderBuilder.
    pub fn new(
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
        atca_iface: rust_cryptoauthlib::AtcaIfaceCfg,
        ) -> Option<Provider> {

        if rust_cryptoauthlib::AtcaStatus::AtcaSuccess != rust_cryptoauthlib::atcab_init(atca_iface) {
            return None;
        }
        let device = rust_cryptoauthlib::atcab_get_device();
        let cryptoauthlib_provider = Provider {
             device,
        };
        return Some(cryptoauthlib_provider);
    }
}

impl Provide for Provider {
    fn describe(&self) -> Result<(ProviderInfo, HashSet<Opcode>)> {
        trace!("describe ingress");
        Ok((ProviderInfo {
            // Assigned UUID for this provider: b8ba81e2-e9f7-4bdd-b096-a29d0019960c
            uuid: Uuid::parse_str("b8ba81e2-e9f7-4bdd-b096-a29d0019960c").or(Err(ResponseStatus::InvalidEncoding))?,
            description: String::from("User space hardware provider, utilizing MicrochipTech CryptoAuthentication Library for ATECCx08 chips"),
            vendor: String::from("Arm"),
            version_maj: 0,
            version_min: 1,
            version_rev: 0,
            id: ProviderID::CryptoAuthLib,
        }, SUPPORTED_OPCODES.iter().copied().collect()))
    }
    
    fn psa_hash_compute(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        trace!("psa_hash_compute ingress");
        self.psa_hash_compute_internal(op)
    }  
}

/// CryptoAuthentication Library Povider builder
#[derive(Default, Derivative)]
#[derivative(Debug)]
pub struct ProviderBuilder {
    #[derivative(Debug = "ignore")]
    key_info_store: Option<Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>>,
    device_type: Option<String>,
    iface_type: Option<String>,
    wake_delay: Option<u16>,
    rx_retries: Option<i32>,
    slave_address: Option<u8>,
    bus: Option<u8>,
    baud: Option<u32>,
}

impl ProviderBuilder {
    /// Create a new CryptoAuthLib builder
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            key_info_store: None,
            device_type: None,
            iface_type: None,
            wake_delay: None,
            rx_retries: None,
            slave_address: None,
            bus: None,
            baud: None,
        }
    }

    /// Add a KeyInfo manager
    pub fn with_key_info_store(
        mut self,
        key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>,
    ) -> ProviderBuilder {
        self.key_info_store = Some(key_info_store);

        self
    }

    /// Specify the ATECC device to be used
    pub fn with_device_type(mut self, device_type: String) -> ProviderBuilder {
        self.device_type = match {
            "atecc508a" | "atecc508a" => Some(device_type),
            _ => None,
        }

        self
    }

    pub fn with_iface_type(mut self, iface_type: String) -> ProviderBuilder {
        self.iface_type = match {
            "i2c" => Some(iface_type),
            _ => None,
        }

        self
    }

    pub fn with_wake_delay(mut self, wake_delay: u16) -> ProviderBuilder {
        self.wake_delay = Some(wake_delay);

        self
    }

    pub fn with_rx_retries(mut self, rx_retries: u16) -> ProviderBuilder {
        self.rx_retries = Some(rx_retries);

        self
    }

    pub fn with_slave_address(mut self, slave_address: u8) -> ProviderBuilder {
    self.slave_address = Some(slave_address);

    self
    }

    pub fn with_bus(mut self, bus: u8) -> ProviderBuilder {
        self.bus = Some(bus);

        self
    }

    pub fn with_baud(mut self, baud: u32) -> ProviderBuilder {
        self.baud = Some(baud);

        self
    }

    /// Attempt to build CryptoAuthLib Provider
    pub fn build(self) -> std::io::Result<Provider> {
        let atca_iface = rust_cryptoauthlib::atca_iface_setup(
            Some(self.device_type),
            Some(self.iface_type),
            Some(self.wake_delay),
            Some(self.rx_retries),
            Some(self.slave_address),
            Some(self.bus),
            Some(self.baud),
            None,
            None,
            None,
            None
        );
        Provider::new(
            self.key_info_store
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing key info store"))?,
            atca_iface,
        )
        .ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "CryptoAuthLib Provider initialization failed",
            )
        })
    }
}
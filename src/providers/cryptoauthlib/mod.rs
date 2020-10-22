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

use rust_cryptoauthlib_sys::{
    ATCADevice,
    ATCAIfaceCfg,
    cfg_ateccx08a_i2c_default,
    cfg_ateccx08a_swi_default,
    cfg_ateccx08a_kitcdc_default,
    cfg_ateccx08a_kithid_default,
    ATCA_STATUS_ATCA_SUCCESS,
    atcab_init,
    atcab_get_device,
};

mod hash;

const SUPPORTED_OPCODES: [Opcode; 1] = [
    Opcode::PsaHashCompute,
];

/// CryptoAuthLib provider structure
#[derive(Derivative)]
#[derivative(Debug, Copy, Clone)]
pub struct Provider {
    device: ATCADevice,
}

impl Provider {
    /// Creates and initialise a new instance of CryptoAuthLibProvider
    // TODO - remove "pub" below. Implement ProviderBuilder.
    pub fn new(interface : String) -> Option<Provider> {
        let mut atca_iface_cfg : ATCAIfaceCfg = match interface.as_ref() {
            "I2C"  => unsafe { cfg_ateccx08a_i2c_default },
            "SWI"  => unsafe { cfg_ateccx08a_swi_default },
            "UART" => unsafe { cfg_ateccx08a_kitcdc_default },
            "HID"  => unsafe { cfg_ateccx08a_kithid_default },
            _ => return None,
        };
        if ATCA_STATUS_ATCA_SUCCESS != unsafe { atcab_init(&mut atca_iface_cfg)} {
            return None;
        }
        let device = unsafe { atcab_get_device() };
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
// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Microchip CryptoAuthentication Library provider
//!
//! This provider is a hardware based implementation of PSA Crypto, Mbed Crypto.
use super::Provide;
use derivative::Derivative;
use log::{error, trace};
use parsec_interface::operations::list_providers::ProviderInfo;

use parsec_interface::operations::{
    // More to come...
//    psa_hash_compare, 
    psa_hash_compute,
};

use parsec_interface::requests::{Opcode, ProviderID, ResponseStatus, Result};

use crate::operations::psa_algorithm::Hash;

use rust_cryptoauthlib_sys;

const SUPPORTED_OPCODES: [Opcode; 2] = [
//    Opcode::PsaHashCompare,
    Opcode::PsaHashCompute,
];

pub struct Provider {
    device: ATCADevice,
}

impl Provider {
    fn new(key_info_store: Arc<RwLock<dyn ManageKeyInfo + Send + Sync>>) -> Option<Provider> {
        if ATCA_SUCCESS != unsafe { atcab_init(&cfg_ateccx08a_i2c_default)} {
            return None;
        }
        let cryptoauthlib_provider = new Provider;
        cryptoauthlib_provider.device = unsafe { atcab_get_device() };
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
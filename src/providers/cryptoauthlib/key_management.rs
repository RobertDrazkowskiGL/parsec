// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::key_info_managers;
use crate::key_info_managers::{KeyInfo, KeyTriple, ManageKeyInfo};
use parsec_interface::requests::ResponseStatus;
use rust_cryptoauthlib;

#[derive(Copy, Clone, Debug)]
pub enum KeySlotStatus {
    /// Slot is free
    Free,
    // InProgress,
    #[allow(dead_code)]
    /// Slot is busy but can be released
    Busy,
    /// Slot is busy and cannot be released, because of hardware protection
    Locked,
}

#[derive(Copy, Clone, Debug)]
pub struct AteccKeySlot {
    pub ref_count: u8,
    pub status: KeySlotStatus,
    pub config: rust_cryptoauthlib::SlotConfig,
}

impl Default for AteccKeySlot {
    fn default() -> AteccKeySlot {
        unsafe { std::mem::zeroed() }
    }
}

impl Provider {
    /// Validate KeyInfo data store entry against hardware
    pub fn validate_key_triple(
        &self,
        key_triple: &KeyTriple,
        store_handle: &dyn ManageKeyInfo,
    ) -> Result<Option<String>, String> {
        // Get CryptoAuthLibProvider mapping of key triple to key info and check
        // (1) if the mapping is between two valid entities - drop key triple if not
        // (2) if the key info matches ATECC configuration - drop key triple if not
        // (3) if there are no two key triples mapping to a single ATECC slot - warning only ATM

        // check (1)
        let key_info = match Provider::get_key_info(key_triple, &*store_handle) {
            Ok(key_info) => key_info,
            Err(response_status) => {
                let error = std::format!(
                    "Error getting the Key ID for triple:\n{}\n(error: {}), continuing...", 
                    key_triple, response_status
                );
                return Err(error);
            }
        };
        // check (2)
        match self.key_info_vs_config(&key_info) {
            Ok(_) => (),
            Err(err) => {
                let error = std::format!(
                    "ATECC slot configuration mismatch for triple:\n{}\n(error: {}), continuing...",
                    key_triple, err
                );
                return Err(error);
            }
        };
        // check(3)
        match self.ref_counter_update(&key_info) {
            Ok(_) => (),
            Err(pair) => {
                let warning = std::format!(
                    "Superfluous reference(s) to ATECC slots {:?}; key triple:\n{}\n, continuing...",
                    pair, key_triple
                );
                return Ok(Some(warning));
            }
        };
        Ok(None)
    }

    fn key_info_vs_config(&self, _key_info: &KeyInfo) -> Result<(), String> {
        // let slot = key_info.id[0];
        // let mut key_slot = self.key_slots.read().unwrap()[slot as usize];
        //
        // (1) Check key_info.attributes.key_type
        // (2) Check key_info.attributes.policy.usage_flags
        // (3) Check key_info.attributes.policy.permitted_algorithms

        Ok(())
    }

    fn ref_counter_update(&self, key_info: &KeyInfo) -> Result<(), (u8,u8)> {
        let slot = key_info.id[0];
        let mut key_slot = self.key_slots.write().unwrap()[slot as usize];
        key_slot.ref_count += 1;
        if 1 < key_slot.ref_count {
            Err((slot,0u8))
        } else {
            Ok(())
        }
    }

    // Get KeyInfo struct from ManageKeyInfo data store handle matching given KeyTriple
    fn get_key_info(
        key_triple: &KeyTriple,
        store_handle: &dyn ManageKeyInfo,
    ) -> Result<KeyInfo, String> {
        match store_handle.get(key_triple) {
            Ok(Some(key_info)) => Ok(KeyInfo{
                id: key_info.id.to_vec(),
                attributes: key_info.attributes,
            }),
            Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist.to_string()),
            Err(string) => Err(key_info_managers::to_response_status(string).to_string()),
        }
    }
}

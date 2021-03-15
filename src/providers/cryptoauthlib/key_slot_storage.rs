// use crate::key_info_managers::KeyTriple;
use crate::providers::cryptoauthlib::key_slot::{AteccKeySlot, KeySlotStatus};
use parsec_interface::operations::psa_key_attributes::Attributes;
use parsec_interface::requests::ResponseStatus;
use std::sync::RwLock;
// use log::warn;

#[derive(Debug)]
pub struct KeySlotStorage {
    storage: RwLock<[AteccKeySlot; rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT as usize]>,
}

impl KeySlotStorage {
    pub fn new() -> KeySlotStorage {
        KeySlotStorage {
            storage: RwLock::new(
                [AteccKeySlot::default(); rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT as usize],
            ),
        }
    }

    /// Validate KeyInfo data store entry against hardware
    /// Mark slot busy when all checks pass
    pub fn key_validate_and_mark_busy(&self, key_info_id: u8, key_info_attributes: &Attributes) -> Result<Option<String>, String> {
        let mut key_slots = self.storage.write().unwrap();

        // Get CryptoAuthLibProvider mapping of key triple to key info and check
        // (1) if the key info matches ATECC configuration - report key triple to b dropped if not
        // (2) if there are no two key triples mapping to a single ATECC slot - warning only ATM

        // check (1)
        match key_slots[key_info_id as usize].key_attr_vs_config(&key_info_attributes) {
            Ok(_) => (),
            Err(err) => {
                let error = std::format!("ATECC slot configuration mismatch: {}", err);
                return Err(error);
            }
        };
        // check(2)
        match key_slots[key_info_id as usize].reference_check_and_set() {
            Ok(_) => (),
            Err(slot) => {
                let warning = std::format!("Superfluous reference(s) to ATECC slot {:?}", slot);
                return Ok(Some(warning));
            }
        };
        // when everything succeedes - set slot as busy
        match key_slots[key_info_id as usize].set_slot_status(KeySlotStatus::Busy) {
            Ok(()) => Ok(None),
            Err(err) => {
                let error = std::format!("Unable to set hardware slot status: {}", err);
                Err(error)
            }
        }
    }

    /// Lock protected per slot hardware configuration setter
    pub fn set_hw_config(&self, hw_config: &[rust_cryptoauthlib::AtcaSlot]) -> Result<(), String> {
        // RwLock protection
        let mut key_slots = self.storage.write().unwrap();
        for slot in 0..rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT {
            if hw_config[slot as usize].id != slot {
                return Err(
                    "configuration mismatch: vector index does not match its id.".to_string(),
                );
            }
            key_slots[slot as usize] = AteccKeySlot {
                ref_count: 0u8,
                status: {
                    match hw_config[slot as usize].is_locked {
                        true => KeySlotStatus::Locked,
                        _ => KeySlotStatus::Free,
                    }
                },
                config: hw_config[slot as usize].config,
            }
        }
        Ok(())
    }

    /// Lock protected set slot status wrapper
    pub fn set_slot_status(
        &self,
        slot_id: usize,
        status: KeySlotStatus,
    ) -> Result<(), ResponseStatus> {
        let mut key_slots = self.storage.write().unwrap();
        key_slots[slot_id].set_slot_status(status)
    }

    /// Iterate through key_slots and find a free one with configuration matching attributes.
    /// If found, the slot is marked Busy.
    pub fn find_suitable_slot(&self, key_attr: &Attributes) -> Result<u8, ResponseStatus> {
        let mut key_slots = self.storage.write().unwrap();
        for slot in 0..rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT {
            if !key_slots[slot as usize].is_free() {
                continue;
            }
            match key_slots[slot as usize].key_attr_vs_config(key_attr) {
                Ok(_) => match key_slots[slot as usize].set_slot_status(KeySlotStatus::Busy) {
                    Ok(()) => return Ok(slot),
                    Err(err) => return Err(err),
                },
                Err(_) => continue,
            }
        }
        Err(ResponseStatus::PsaErrorInsufficientStorage)
    }
}

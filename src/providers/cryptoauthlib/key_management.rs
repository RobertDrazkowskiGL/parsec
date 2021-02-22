// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::key_info_managers;
use crate::key_info_managers::{KeyInfo, KeyTriple, ManageKeyInfo};
use parsec_interface::requests::ResponseStatus;
use parsec_interface::operations::psa_key_attributes::{ EccFamily, Type};
use parsec_interface::operations::psa_algorithm::{ Algorithm, Aead, AeadWithDefaultLengthTag, 
    AsymmetricSignature, Cipher, FullLengthMac, Hash, KeyAgreement, Mac, RawKeyAgreement, SignHash};
use rust_cryptoauthlib;

#[derive(Copy, Clone, Debug, PartialEq)]
/// Software status of a ATECC slot
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
/// Hardware slot information
pub struct AteccKeySlot {
    /// Diagnotic field. Number of key triples pointing at this slot
    pub ref_count: u8,
    /// Slot status
    pub status: KeySlotStatus,
    /// Hardware configuration of a slot
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
                    key_triple, response_status.to_string()
                );
                return Err(error);
            }
        };
        // check (2)
        let key_slot = {
            let lock = self.key_slots.read().unwrap();
            lock[key_info.id[0] as usize]
        };
        match self.key_info_vs_config(&key_info, key_slot) {
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

    // Check if software key attributes are compatible with hardware slot configuration
    fn key_info_vs_config(
        &self, 
        key_info: &KeyInfo,
        key_slot: AteccKeySlot
    ) -> Result<(), ResponseStatus> {
        // (1) Check key_info.attributes.key_type
        if !Provider::key_type_ok(key_info, key_slot) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }
        // (2) Check key_info.attributes.policy.usage_flags
        if !Provider::usage_flags_ok(key_info, key_slot) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        }        
        // (3) Check key_info.attributes.policy.permitted_algorithms
        if !Provider::algorithms_ok(key_info, key_slot) {
            return Err(ResponseStatus::PsaErrorNotSupported);
        } 

        Ok(())
    }

    fn key_type_ok(
        key_info: &KeyInfo,
        key_slot: AteccKeySlot
    ) -> bool {
        match key_info.attributes.key_type {
            Type::RawData => {
                key_slot.config.key_type == rust_cryptoauthlib::KeyType::ShaOrText
            },
            Type::Hmac => {
                key_slot.config.no_mac == false
            },
            Type::Aes => {
                key_slot.config.key_type == rust_cryptoauthlib::KeyType::Aes
            },
            Type::EccKeyPair { curve_family: EccFamily::SecpR1 } |
            Type::EccPublicKey { curve_family: EccFamily::SecpR1 } => {
                key_info.attributes.bits == 256 &&
                key_slot.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
            },
            Type::Derive             |
            Type::DhKeyPair   { .. } |
            Type::DhPublicKey { .. } => {
                // This may change...
                false
            }
            _ => false,
        }
    }

    fn usage_flags_ok(
        key_info: &KeyInfo,
        key_slot: AteccKeySlot
    ) -> bool {
        let mut result = true;
        if key_info.attributes.policy.usage_flags.export ||
            key_info.attributes.policy.usage_flags.copy {
            result &= match key_slot.config.key_type {
                rust_cryptoauthlib::KeyType::Aes => true,
                rust_cryptoauthlib::KeyType::P256EccKey => {
                    key_slot.config.pub_info == true && 
                    match key_info.attributes.key_type {
                        Type::EccPublicKey { .. } |
                        Type::DhPublicKey  { .. } => true,
                        _ => false,
                    }
                },
                _ => true,
            }
        }
        if !result {
            return false;
        }
        if key_info.attributes.policy.usage_flags.sign_hash ||
            key_info.attributes.policy.usage_flags.sign_message {
            result &= key_slot.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey;
            result &= key_slot.config.ecc_key_attr.is_private == true;
        }
        return result;
    }

    fn algorithms_ok(
        key_info: &KeyInfo,
        key_slot: AteccKeySlot
    ) -> bool {
        match key_info.attributes.policy.permitted_algorithms {
            // Hash algorithm
            Algorithm::Hash(Hash::Sha256) => true,
            // Mac::Hmac algorithm
            Algorithm::Mac(Mac::Truncated {
                mac_alg: FullLengthMac::Hmac {
                    hash_alg: Hash::Sha256
                },
                ..
            })
            | Algorithm::Mac(Mac::FullLength (
                FullLengthMac::Hmac {
                    hash_alg: Hash::Sha256
                })) => {
                key_slot.config.no_mac == false &&
                key_slot.config.key_type != rust_cryptoauthlib::KeyType::P256EccKey &&
                key_slot.config.ecc_key_attr.is_private == false
            },
            // Mac::CbcMac and Mac::Cmac algorithms
            Algorithm::Mac(Mac::Truncated {
                mac_alg: FullLengthMac::CbcMac,
                ..
            })
            | Algorithm::Mac(Mac::FullLength(FullLengthMac::CbcMac))
            | Algorithm::Mac(Mac::Truncated {
                mac_alg: FullLengthMac::Cmac,
                ..
            })
            | Algorithm::Mac(Mac::FullLength(FullLengthMac::Cmac)) => {
                key_slot.config.no_mac == false &&
                key_slot.config.key_type == rust_cryptoauthlib::KeyType::Aes
            }
            // Cipher
            Algorithm::Cipher(Cipher::CbcPkcs7) |
            Algorithm::Cipher(Cipher::Ctr) |
            Algorithm::Cipher(Cipher::Cfb) |
            Algorithm::Cipher(Cipher::Ofb) => key_slot.config.key_type == rust_cryptoauthlib::KeyType::Aes,
            // Aead
            Algorithm::Aead(Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Ccm)) |
            Algorithm::Aead(Aead::AeadWithDefaultLengthTag(AeadWithDefaultLengthTag::Gcm)) |
            Algorithm::Aead(Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Ccm,
                ..
            }) |
            Algorithm::Aead(Aead::AeadWithShortenedTag {
                aead_alg: AeadWithDefaultLengthTag::Gcm,
                ..
            }) => key_slot.config.key_type == rust_cryptoauthlib::KeyType::Aes,
            // AsymmetricSignature
            Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                hash_alg: SignHash::Specific(Hash::Sha256)
            }) => {
                key_slot.config.is_secret == true &&
                key_slot.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey &&
                key_slot.config.ecc_key_attr.is_private == true
                // TODO: what is external or internal hashing?
            },
            Algorithm::AsymmetricSignature(AsymmetricSignature::DeterministicEcdsa {
                hash_alg: SignHash::Specific(Hash::Sha256)
            }) => {
                // RFC 6979
                false
            },
            // AsymmetricEncryption
            Algorithm::AsymmetricEncryption(..) => {
                // why only RSA? it could work with ECC...
                false
            },
            // KeyAgreement
            Algorithm::KeyAgreement(KeyAgreement::Raw(RawKeyAgreement::Ecdh)) |
            Algorithm::KeyAgreement(KeyAgreement::WithKeyDerivation {
                ka_alg: RawKeyAgreement::Ecdh,
                ..
            }) => {
                key_slot.config.key_type == rust_cryptoauthlib::KeyType::P256EccKey
            },
            // Nothing else is known to be supported by Atecc
            _ => false, 
        }
    }

    /// Iterate through key_slots and find a free one with configuration matching attributes from key_info.
    /// If found, the slot is marked Busy.
    pub fn find_suitable_slot(&self, key_info: &KeyInfo) -> Result<(u8,u8), ResponseStatus> {
        let mut key_slots = self.key_slots.write().unwrap();
        for slot in 0..rust_cryptoauthlib::ATCA_ATECC_SLOTS_COUNT {
            if KeySlotStatus::Free != key_slots[slot as usize].status {
                continue;
            }
            match self.key_info_vs_config(key_info,key_slots[slot as usize]) {
                Ok(_) => {
                    key_slots[slot as usize].status = KeySlotStatus::Busy;
                    return Ok((slot,0u8));
                },
                Err(_) => continue,
            }
        }
        Err(ResponseStatus::PsaErrorStorageFailure)
    }
    
    // fn set_slot_status()
    // fn try_release_key()


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
    ) -> Result<KeyInfo, ResponseStatus> {
        match store_handle.get(key_triple) {
            Ok(Some(key_info)) => {
                if 0 == key_info.id.len() {
                    format_error!(
                        "Stored Key ID is not valid.",
                        ResponseStatus::KeyInfoManagerError
                    );
                    Err(ResponseStatus::KeyInfoManagerError)
                } else {
                    Ok(KeyInfo {
                        id: key_info.id.to_vec(),
                        attributes: key_info.attributes,
                    })
                }
            },
            Ok(None) => Err(ResponseStatus::PsaErrorDoesNotExist),
            Err(string) => Err(key_info_managers::to_response_status(string)),
        }
    }
}

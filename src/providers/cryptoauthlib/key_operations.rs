// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::key_slot::KeySlotStatus;
use super::Provider;
use crate::authenticators::ApplicationName;
use log::{error, warn};
use parsec_interface::operations::{psa_destroy_key, psa_generate_key, psa_export_public_key};
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);

        self.key_info_store.does_not_exist(&key_triple)?;
        let key_attributes = op.attributes;
        let key_type = Provider::get_calib_key_type(&key_attributes).map_err(|e| {
            error!("Failed to get type for key. {}", e);
            e
        })?;
        let slot_id = self.find_suitable_slot(&key_attributes).map_err(|e| {
            warn!("Failed to find suitable storage slot for key. {}", e);
            e
        })?;
        // generate key
        match self.device.gen_key(key_type, slot_id) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                match self
                    .key_info_store
                    .insert_key_info(key_triple, &slot_id, key_attributes)
                {
                    Ok(()) => Ok(psa_generate_key::Result {}),
                    Err(error) => {
                        error!("Insert key triple to KeyInfoManager failed. {}", error);
                        self.set_slot_status(slot_id as usize, KeySlotStatus::Free)
                            .ok()
                            .ok_or(error)?;
                        Err(error)
                    }
                }
            }
            _ => {
                let error = ResponseStatus::PsaErrorInvalidArgument;
                error!(
                    "Key generation failed. Trying to update slot status. {}",
                    error
                );
                self.set_slot_status(slot_id as usize, KeySlotStatus::Free)
                    .ok()
                    .ok_or(error)?;
                Err(error)
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);

        match self.key_info_store.remove_key_info(&key_triple) {
            Ok(key_info) => {
                match self.set_slot_status(key_info.id[0] as usize, KeySlotStatus::Free) {
                    Ok(()) => (),
                    Err(error) => {
                        warn!(
                            "Could not set slot {:?} as free because {}",
                            key_info.id[0], error,
                        );
                    }
                }
                Ok(psa_destroy_key::Result {})
            }
            Err(error) => {
                warn!("Key {} removal reported an error: - {}", key_triple, error);
                Err(error)
            }
        }
    }
    pub(super) fn psa_export_public_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_export_public_key::Operation,
    ) -> Result<psa_export_public_key::Result> {
        let key_name = op.key_name;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);
        let slot_number = self.key_info_store.get_key_id(&key_triple)?;
        let mut public_key = Vec::new();

        match self.device.get_public_key(slot_number, &mut public_key) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                Ok(psa_export_public_key::Result {data: public_key.into()})
            }
            _ => {
                let error = ResponseStatus::PsaErrorInvalidArgument;
                error!("Export public key failed. {}", error);
                Err(error)
            }
        }

    }
}

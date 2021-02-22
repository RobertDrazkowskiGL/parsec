use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;

use super::key_management::KeySlotStatus;
use parsec_interface::operations::{
    psa_destroy_key, psa_generate_key
};
use log::{error, warn};
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        // create key triple
        let key_attributes = op.attributes;
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::CryptoAuthLib, key_name);
        let mut store_handle = self.key_info_store.write().expect("Key store lock poisoned");

        match Provider::get_key_info(&key_triple, &*store_handle) {
            Ok(key_info) => key_info,
            Err(response_status) => Err(response_status), // todo
        };
        let slot_id = match self.find_suitable_slot(&key_info) { // todo
            Ok((slot, step)) => slot,
            Err(status) => warn!("{}", status), // todo
        };

        // generate key
        // ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t *public_key)
        match self.device.gen_key(key_type, slot_id) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                // TODO: update mapping triple-info
                 Ok(psa_generate_key::Result {})
            }
            _ => {
                // update slot status back to free
                Provider::set_slot_status(
                    &mut self.key_slots.write().unwrap()[slot_id as usize],
                    KeySlotStatus::Free,
                );
                let error = ResponseStatus::PsaErrorGenericError;
                format_error!("Key generation failed ", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        app_name: ApplicationName,
        op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        // create key triple
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::CryptoAuthLib, key_name);

        match self.try_release_key(&key_triple) {
            Ok(_x) => {
                Ok(psa_destroy_key::Result {})
            }
            Err(string) => {
                error!("{}", string);
                Err(ResponseStatus::PsaErrorNotPermitted)
            }
        }
    }
}

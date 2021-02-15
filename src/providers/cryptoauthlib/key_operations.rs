use super::Provider;
use crate::authenticators::ApplicationName;

use parsec_interface::requests::Result;
use parsec_interface::operations::{
    psa_destroy_key, psa_generate_key
};

impl Provider {
    pub(super) fn psa_generate_key_internal(
        &self,
        _app_name: ApplicationName,
        _op: psa_generate_key::Operation,
    ) -> Result<psa_generate_key::Result> {
        // create key triple
        let key_attributes = op.attributes;
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::CryptoAuthLib, key_name);
        // find suitable key id
        let key_id = 0; // placeholder
        // generate key
        // ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t *public_key)
        match self.device.genkey(key_id, &public_key) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                // update atca_slots
                Ok(psa_generate_key::Result {})
            }
            _ => {
                let error = ResponseStatus::PsaErrorGenericError;
                format_error!("Key generation failed ", err);
                Err(error)
            }
        }
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        _app_name: ApplicationName,
        _op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        // create key triple
        // get key_id
        // destroy key
        // update storage

        Ok(psa_destroy_key::Result {})
    }
}

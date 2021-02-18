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

        // TODO: find suitable key id
        let key_info = Provider::get_key_info(&key_triple);
        let key_id = Provider::find_suitable_slot(&key_info);
        let public_key = Vec::new(); // type might change

        // generate key
        // ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t *public_key)
        match self.device.genkey(key_id, &public_key) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                // TODO: update mapping triple-info
                Ok(psa_generate_key::Result {})
            }
            _ => {
                // update slot status back to free
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
        let key_name = op.key_name;
        let key_triple = KeyTriple::new(app_name, ProviderID::CryptoAuthLib, key_name);

        match self.try_release_slot(&key_triple) {
            Ok => {
                Ok(psa_destroy_key::Result {})
            }
            Err(string) => {
                error!(string);
                Err()
            }
        }
    }
}

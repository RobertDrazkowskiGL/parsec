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
        Ok(psa_generate_key::Result {})
    }

    pub(super) fn psa_destroy_key_internal(
        &self,
        _app_name: ApplicationName,
        _op: psa_destroy_key::Operation,
    ) -> Result<psa_destroy_key::Result> {
        Ok(psa_destroy_key::Result {})
    }
}

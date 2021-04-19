// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use log::warn;
use parsec_interface::operations::psa_sign_hash;
use parsec_interface::requests::{ProviderID, ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_triple = KeyTriple::new(app_name, ProviderID::CryptoAuthLib, op.key_name.clone());
        let key_id = self.key_info_store.get_key_id::<u8>(&key_triple)?;
        let key_attributes = self.key_info_store.get_key_attributes(&key_triple)?;

        op.validate(key_attributes)?;

        let mut signature = vec![0u8; rust_cryptoauthlib::ATCA_SIG_SIZE];
        let hash = op.hash.to_vec();
        let result = self.device.sign_hash(
            rust_cryptoauthlib::SignMode::External(hash),
            key_id,
            &mut signature,
        );
        match result {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => Ok(psa_sign_hash::Result {
                signature: signature.into(),
            }),
            _ => {
                warn!("Sign failed: {}", result);
                Err(ResponseStatus::PsaErrorHardwareFailure)
            }
        }
    }
}

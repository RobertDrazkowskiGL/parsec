// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use crate::key_info_managers::KeyTriple;
use parsec_interface::operations::{psa_sign_hash, psa_verify_hash};
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
        match self.device.sign_hash(
            rust_cryptoauthlib::SignMode::External(hash),
            key_id,
            &mut signature,
        ) {
            rust_cryptoauthlib::AtcaStatus::AtcaSuccess => Ok(psa_sign_hash::Result {
                signature: signature.into(),
            }),
            _ => {
                let error = ResponseStatus::PsaErrorNotPermitted;
                format_error!("Sign status: ", error);
                Err(error)
            }
        }
    }

    pub(super) fn psa_verify_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_verify_hash::Operation,
    ) -> Result<psa_verify_hash::Result> {
        let key_name = op.key_name.clone();
        let hash = op.hash.clone();
        let signature = op.signature.clone();
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);
        let key_info = match self.get_key_info(&key_triple) {
            Ok(key_info) => key_info,
            Err(error) => return Err(error),
        };
        match op.validate(key_info.attributes) {
            Ok(()) => (),
            Err(error) => return Err(error),
        }

        // pub fn verify_hash(&self, mode: VerifyMode, hash: &[u8], signature: &[u8]) -> Result<bool, AtcaStatus>
        match self.device.verify_hash(
            rust_cryptoauthlib::VerifyMode::Internal(key_info.id[0]),
            &hash,
            &signature,
        ) {
            Ok(is_verified) => {
                if !is_verified {
                    let error = ResponseStatus::PsaErrorInvalidSignature;
                    format_error!("Verify status: ", error);
                    return Err(error);
                }
                Ok(psa_verify_hash::Result {})
            }
            Err(status) => {
                format_error!("Verify status: ", status);
                Err(ResponseStatus::PsaErrorGenericError)
            }
        }
    }
}

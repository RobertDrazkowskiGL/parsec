// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use crate::authenticators::ApplicationName;
use parsec_interface::operations::psa_sign_hash;
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_sign_hash_internal(
        &self,
        app_name: ApplicationName,
        op: psa_sign_hash::Operation,
    ) -> Result<psa_sign_hash::Result> {
        let key_name = op.key_name;
        let hash = op.hash;
        let alg = op.alg;
        let key_triple = self.key_info_store.get_key_triple(app_name, key_name);
        let key_info = match self.get_key_info(&key_triple) {
            Ok(key_info) => key_info,
            Err(error) => return Err(error),
        };
        match op.validate(key_info.attributes) {
            Ok(()) => (),
            Err(error) => return Err(error),
        }

        let mut signature = vec![0u8; 64]; // use const
        match self.device.sign_hash(key_info.id, alg, &hash, &mut signature) {
            Ok(size) => {
                signature.resize(size, 0);
                Ok(psa_sign_hash::Result {
                    signature: signature.into(),
                })
            }
            Err(error) => {
                let error = ResponseStatus::from(error);
                format_error!("Sign status: ", error);
                Err(error)
            }
        }
    }
}
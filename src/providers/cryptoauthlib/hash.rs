// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::psa_algorithm::Hash;
use parsec_interface::operations::psa_hash_compute;
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_hash_compute_internal(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        let mut hash = vec![0u8; op.alg.hash_length()];
        let message = op.input.to_vec();
        match op.alg {
            Hash::Sha256 => {
                match rust_cryptoauthlib::atcab_sha(
                    message,
                    &mut hash,
                ) {
                    rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                        Ok(psa_hash_compute::Result { hash: hash.into() })
                    }
                    err => {
                        let error = ResponseStatus::PsaErrorGenericError;
                        format_error!("Hash computation failed ", err);
                        Err(error)
                    }
                }
            }
            _ => {
                let error = ResponseStatus::PsaErrorNotSupported;
                format_error!("Unsupported hash algorithm ", error);
                Err(error)
            }
        }
    }
}

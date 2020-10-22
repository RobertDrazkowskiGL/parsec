// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::psa_algorithm::Hash;
use parsec_interface::operations::psa_hash_compute;
use parsec_interface::requests::{ResponseStatus, Result};
use rust_cryptoauthlib_sys;

impl Provider {
    pub(super) fn psa_hash_compute_internal(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        let mut hash = vec![0u8; op.alg.hash_length()];
        let message = op.input.as_ptr();
        match op.alg {
            Hash::Sha256 => {
                match  unsafe { rust_cryptoauthlib_sys::atcab_sha(op.input.len() as u16, message, hash.as_mut_ptr()) } {
                    rust_cryptoauthlib_sys::ATCA_STATUS_ATCA_SUCCESS => {
                        Ok(psa_hash_compute::Result { hash: hash.into() })
                    }
                    _ => {
                        let error = ResponseStatus::PsaErrorGenericError;
                        format_error!("Hash computation failed ", error);
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

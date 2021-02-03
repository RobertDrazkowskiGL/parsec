// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::psa_algorithm::Hash;
use parsec_interface::operations::psa_hash_compare;
use parsec_interface::operations::psa_hash_compute;
use parsec_interface::requests::{ResponseStatus, Result};

impl Provider {
    pub(super) fn psa_hash_compute_internal(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        let mut hash = vec![0u8; op.alg.hash_length()];
        match op.alg {
            Hash::Sha256 => {
                let message = op.input.to_vec();

                let err = {
                    // critical section start
                    let _guard = self
                        .atcab_api_mutex
                        .lock()
                        .expect("Could not lock atcab API mutex");
                    rust_cryptoauthlib::atcab_sha(message, &mut hash)
                    // critical section end
                };
                match err {
                    rust_cryptoauthlib::AtcaStatus::AtcaSuccess => {
                        Ok(psa_hash_compute::Result { hash: hash.into() })
                    }
                    _ => {
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

    pub(super) fn psa_hash_compare_internal(
        &self,
        op: psa_hash_compare::Operation,
    ) -> Result<psa_hash_compare::Result> {
        let op_hash = op.hash.to_vec();
        let alg_len = op.alg.hash_length();
        // calculate input hash
        let op_compute = psa_hash_compute::Operation {
            alg: op.alg,
            input: op.input,
        };
        match self.psa_hash_compute_internal(op_compute) {
            Ok(psa_hash_compute::Result { hash }) => {
                // compare hashes length
                if op_hash.len() != alg_len || hash.as_slice().len() != alg_len {
                    let error = ResponseStatus::PsaErrorInvalidArgument;
                    format_error!("Hash length comparison failed: ", error);
                    return Err(error);
                }
                // compare hashes
                if op_hash != hash.as_slice() {
                    let error = ResponseStatus::PsaErrorInvalidSignature;
                    format_error!("Hash comparison failed: ", error);
                    return Err(error);
                }
                // return result
                Ok(psa_hash_compare::Result)
            }
            _ => {
                let error = ResponseStatus::PsaErrorGenericError;
                format_error!("Hash computation failed ", error);
                Err(error)
            }
        }
    }
}

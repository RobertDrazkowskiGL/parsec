// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::Provider;
use parsec_interface::operations::{psa_hash_compute};
use parsec_interface::requests::{ResponseStatus, Result};
use rust_cryptoauthlib_sys;

impl Provider {
    pub(super) fn psa_hash_compute_internal(
        &self,
        op: psa_hash_compute::Operation,
    ) -> Result<psa_hash_compute::Result> {
        // let mut hash = vec![0u8; op.alg.hash_length()];

        // match hash::hash_compute(op.alg, &op.input, &mut hash) {
        //     Ok(hash_size) => {
        //         hash.resize(hash_size, 0);
        //         Ok(psa_hash_compute::Result { hash: hash.into() })
        //     }
        //     Err(error) => {
        //         let error = ResponseStatus::from(error);
        //         format_error!("Has compute status: ", error);
        //         Err(error)
        //     }
        // }
        match op.alg {
            let mut hash = vec![0u8; op.alg.hash_length()];
            Hash::Sha256 => {
                match ( unsafe { atcab_sha(op.input.len(),op.input.as_mut(), hash.as_mut_ptr()) }) {
                    ATCA_SUCCESS => {
                        OK(())
                    }
                    _ => {
                        Err("Hash computation failed")
                    }
                }
            }
            _ => {
                let error = ResponseStatus::PsaErrorNotSupported;
                format_error!("Unsupported hash algorithm: ", op.alg);
                Err(error)
            }
        }
    }
}

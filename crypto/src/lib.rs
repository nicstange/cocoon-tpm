// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]

use cocoon_tpm_tpm2_interface as tpm2_interface;
use cocoon_tpm_utils_common as utils_common;

#[cfg(feature = "ecc")]
pub mod ecc;
mod error;
pub mod hash;
mod io_slices;
pub mod kdf;
pub mod rng;
#[cfg(feature = "rsa")]
pub mod rsa;
pub mod symcipher;

#[cfg(not(feature = "boringssl"))]
mod pure_rust;
#[cfg(not(feature = "boringssl"))]
use pure_rust as backend;
#[cfg(feature = "boringssl")]
mod bssl_ffi;
#[cfg(feature = "boringssl")]
use bssl_ffi as backend;

pub use error::*;
pub use io_slices::*;

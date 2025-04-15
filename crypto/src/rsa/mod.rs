// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! RSA implementation.

mod crt;
mod encrypt;
mod key;
mod keygen;
#[cfg(feature = "oaep")]
pub mod oaep;
#[cfg(feature = "rsapss")]
pub mod pss;
#[cfg(feature = "rsaes")]
pub mod es_pkcs1_v1_5;
#[cfg(feature = "rsassa")]
pub mod ssa_pkcs1_v1_5;

pub use key::*;

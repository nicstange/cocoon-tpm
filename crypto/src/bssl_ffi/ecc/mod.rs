// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! BoringSSL FFI backend for ECC.

pub mod bssl_ec_key;
pub mod curve;
#[cfg(feature = "ecdh")]
pub mod ecdh;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;

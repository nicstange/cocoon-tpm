// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Pure Rust backend for ECC.

pub mod curve;
#[cfg(feature = "ecdh")]
pub mod ecdh;
#[cfg(feature = "ecdsa")]
pub mod ecdsa;

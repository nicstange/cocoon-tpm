// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Pure Rust backend [Random Number Generator](crate::rng) implementations.

#[cfg(all(feature = "enable_x86_64_rdseed", target_arch = "x86_64"))]
mod x86_64_rdseed;
#[cfg(all(feature = "enable_x86_64_rdseed", target_arch = "x86_64"))]
pub use x86_64_rdseed::*;

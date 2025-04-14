// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]

use cocoon_tpm_utils_common as utils_common;

mod error;
mod io_slices;

pub use error::*;
pub use io_slices::*;

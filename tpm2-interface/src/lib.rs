// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

#![no_std]
#![macro_use]

mod interface;
pub use interface::*;

/// Convenience helper to instantiate [`TpmRc`].
///
/// # Example:
///
/// ```
/// fn foo() -> TpmRc {
///     tpm_rc!(MEMORY)
/// }
/// ```
#[allow(unused)]
macro_rules! tpm_rc {
    ($rc:ident) => {
        TpmRc::$rc
    };
}

/// Convenience helper to instantiate [`TpmErr::Rc`].
///
/// # Example:
///
/// ```
/// fn foo() -> TpmErr {
///     tpm_err_rc!(MEMORY)
/// }
/// ```
#[allow(unused)]
macro_rules! tpm_err_rc {
    ($rc:ident) => {
        TpmErr::Rc(tpm_rc!($rc))
    };
}

/// Convenience helper to instantiate [`TpmErr::InternalErr`].
///
/// Any attempts to instantiate a `[`TpmErr::InternalErr`] through this macro
/// will cause a panic in debug builds.
#[allow(unused)]
macro_rules! tpm_err_internal {
    () => {
        if cfg!(debug_assertions) {
            panic!("TpmErr::InternalErr");
        } else {
            TpmErr::InternalErr {}
        }
    };
}

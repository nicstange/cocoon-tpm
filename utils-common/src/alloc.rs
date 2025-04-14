// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Helpers related to `alloc`.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use core::{mem, ptr};

use crate::zeroize;

/// Memory allocation error.
#[derive(Clone, Copy, Debug)]
pub enum TryNewError {
    /// Memory allocation failure.
    MemoryAllocationFailure,
}

/// Try to allocate a `Box`, handling allocation failure gracefully.
///
/// Currently `Box::try_new()` is still unstable, so this implements an
/// alternative Box instantiation primitive enabling graceful memory allocation
/// failure handling.
///
/// # Arguments:
///
/// * `v` - The value to wrap in a `Box`.
///
/// # Errors:
///
/// * [`TryNewError::MemoryAllocationFailure`] - The memory allocation has
///   failed.
pub fn box_try_new<T>(v: T) -> Result<Box<T>, TryNewError> {
    // Box::try_new() is unstable, so do it by ourselves for now.
    // Refer to https://doc.rust-lang.org/std/boxed/index.html#memory-layout.
    let p: *mut T = if mem::size_of::<T>() == 0 {
        // Dangling pointers are valid for ZSTs and the write below is Ok.
        ptr::NonNull::dangling().as_ptr()
    } else {
        let layout = alloc::alloc::Layout::new::<T>();
        let p: *mut T = unsafe { alloc::alloc::alloc(layout) } as *mut T;
        if p.is_null() {
            return Err(TryNewError::MemoryAllocationFailure);
        }
        p
    };

    unsafe { p.write(v) };

    Ok(unsafe { Box::from_raw(p) })
}

/// Error returned by [`box_try_new_with()`](box_try_new_with).
#[derive(Clone, Copy, Debug)]
pub enum TryNewWithError<E> {
    /// Memory allocation failure.
    TryNew(TryNewError),
    /// The object factory callback passed to
    /// [`box_try_new_with()`](box_try_new_with) returned an error, wrapped
    /// in the variant.
    With(E),
}

/// Try to initialize a `Box` from a provided factory callback.
///
/// Invoke `f()` to obtain the `Box`' wrapped value only after the heap memory
/// allocation has succeeded and store the returned object in the `Box`.
///
/// This enables the compiler to elide some stack copies unders certain
/// conditions, because might be possible for `f()` to construct the object
/// directly in place on the heap. Note that if `E` is
/// not [`Infallible`](core::convert::Infallible), a stack copy might still be
/// needed to unpeel a returned `Ok()` and extract the wrapped value. However,
/// for huge objects it's been empirically observed that one out of up to two
/// stack copies can usually get eliminated as compared to the "common" `Box`
/// creation primitives.
///
/// # Arguments:
///
/// * `f` - Callback to invoke after memory allocation for obtaining the `Box`'
///   wrapped value. May return an error, which would get propagated via
///   [`TryNewWithError::With`] back to the caller.
///
/// # Errors:
///
/// * [`TryNewWithError::TryNew`] - The memory allocation has failed.
/// * [`TryNewWithError::With`] - The `f` object factory callback returned an
///   error.
pub fn box_try_new_with<T, E, F: FnOnce() -> Result<T, E>>(f: F) -> Result<Box<T>, TryNewWithError<E>> {
    let mut p = box_try_new::<mem::MaybeUninit<T>>(mem::MaybeUninit::uninit()).map_err(TryNewWithError::TryNew)?;
    p.write(match f() {
        Ok(v) => v,
        Err(e) => {
            return Err(TryNewWithError::With(e));
        }
    });
    Ok(unsafe { p.assume_init() })
}

/// Convenience helper to allocate a default-initialized `Vec` of a given
/// length, handling memory allocation failure gracefully.
///
/// # Arguments:
///
/// * `len` - The length to resize the `Vec` to.
///
/// # Errors:
///
/// * [`TryNewError::MemoryAllocationFailure`] - The memory allocation has
///   failed.
pub fn try_alloc_vec<T: Default + Clone>(len: usize) -> Result<Vec<T>, TryNewError> {
    let mut v = Vec::new();
    v.try_reserve_exact(len)
        .map_err(|_| TryNewError::MemoryAllocationFailure)?;
    v.resize(len, T::default());
    Ok(v)
}

/// Convenience helper to allocate a default-initialized and
/// [`Zeroizing`](zeroize::Zeroizing) wrapped `Vec` of a given length
/// handling memory allocation failure gracefully.
///
/// # Arguments:
///
/// * `len` - The length to resize the `Vec` to.
///
/// # Errors:
///
/// * [`TryNewError::MemoryAllocationFailure`] - The memory allocation has
///   failed.
pub fn try_alloc_zeroizing_vec<T: zeroize::Zeroize + Default + Clone>(
    len: usize,
) -> Result<zeroize::Zeroizing<Vec<T>>, TryNewError> {
    Ok(try_alloc_vec(len)?.into())
}

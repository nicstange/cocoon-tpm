// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

use crate::error::CryptoError;

use core::{convert, ffi};

pub struct BSSLError {
    pub packed_error: u32,
}

impl BSSLError {
    pub fn is_code(&self, expected_lib: ffi::c_uint, expected_reason: ffi::c_int) -> bool {
        let unpacked_lib = unsafe { bssl_bare_sys::ERR_GET_LIB(self.packed_error) };
        let unpacked_reason = unsafe { bssl_bare_sys::ERR_GET_REASON(self.packed_error) };
        unpacked_lib as ffi::c_uint == expected_lib && unpacked_reason == expected_reason
    }
}

pub fn bssl_get_raw_error() -> Option<BSSLError> {
    let packed_error = unsafe { bssl_bare_sys::ERR_get_error() };
    if packed_error != 0 {
        // Clear the rest from the queue.
        unsafe { bssl_bare_sys::ERR_clear_error() };
        Some(BSSLError { packed_error })
    } else {
        None
    }
}

pub fn bssl_get_error() -> CryptoError {
    bssl_get_raw_error()
        .map(CryptoError::from)
        .unwrap_or(CryptoError::Internal)
}

impl convert::From<BSSLError> for CryptoError {
    fn from(value: BSSLError) -> Self {
        let reason = unsafe { bssl_bare_sys::ERR_GET_REASON(value.packed_error) };

        // "The following values are global reason codes. They may occur in any
        // library."
        match reason {
            bssl_bare_sys::ERR_R_FATAL => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_MALLOC_FAILURE => return CryptoError::MemoryAllocationFailure,
            bssl_bare_sys::ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_PASSED_NULL_PARAMETER => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_INTERNAL_ERROR => return CryptoError::Internal,
            bssl_bare_sys::ERR_R_OVERFLOW => return CryptoError::Internal,
            _ => (),
        }

        let lib = unsafe { bssl_bare_sys::ERR_GET_LIB(value.packed_error) };
        match lib as ffi::c_uint {
            bssl_bare_sys::ERR_LIB_NONE => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_SYS => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_BN => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_RSA => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_DH => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_EVP => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_BUF => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_OBJ => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_PEM => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_DSA => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_X509 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ASN1 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CONF => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CRYPTO => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_EC => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_SSL => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_BIO => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_PKCS7 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_PKCS8 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_X509V3 => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_RAND => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ENGINE => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_OCSP => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_UI => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_COMP => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ECDSA => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_ECDH => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_HMAC => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_DIGEST => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CIPHER => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_HKDF => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_TRUST_TOKEN => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_CMS => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_LIB_USER => CryptoError::UnspecifiedFailure,
            bssl_bare_sys::ERR_NUM_LIBS => CryptoError::UnspecifiedFailure,
            _ => CryptoError::Internal,
        }
    }
}

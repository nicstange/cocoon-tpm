// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Common interface to symmetric cipher algorithm implementations.
//!
//! # High level overview:
//!
//! For both, encryption and decryption with block ciphers, a
//! [`SymBlockCipherInstance`] must first
//! get instantiated either [directly with a raw key byte
//! slice](SymBlockCipherInstance::new) or through a
//! [`SymBlockCipherKey`](SymBlockCipherKey::instantiate_block_cipher). That
//! instance can then be used to [encrypt](SymBlockCipherInstance::encrypt) or
//! [decrypt](SymBlockCipherInstance::decrypt) one or more message with a
//! specified [block cipher chaining mode](tpm2_interface::TpmiAlgCipherMode)
//! each.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};

use crate::{
    io_slices::{CryptoPeekableIoSlicesMutIter, CryptoWalkableIoSlicesIter, CryptoWalkableIoSlicesMutIter},
    rng, CryptoError,
};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::{box_try_new_with, try_alloc_zeroizing_vec},
        bitmanip::BitManip as _,
        io_slices::{self, IoSlicesIterCommon as _, IoSlicesMutIter as _},
        zeroize,
    },
};
use core::{convert, ops::Deref as _};

use cipher::{BlockDecryptMut as _, BlockEncryptMut as _, IvState as _};
#[allow(unused_imports)]
use crypto_common::{
    self, BlockSizeUser as _, InnerInit as _, InnerIvInit as _, IvSizeUser as _, KeyInit as _, KeySizeUser as _,
};
use generic_array::typenum::Unsigned as _;

#[cfg(feature = "aes")]
use aes;
#[cfg(feature = "camellia")]
use camellia;
#[cfg(feature = "cbc")]
use cbc;
#[cfg(feature = "cfb")]
use cfb_mode;
#[cfg(feature = "ctr")]
mod ctr_impl;
#[cfg(feature = "ecb")]
use ecb;
#[cfg(feature = "ofb")]
use ofb;
#[cfg(feature = "sm4")]
use sm4;

/// AES key sizes.
#[cfg(feature = "aes")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherAesKeySize {
    Aes128,
    Aes192,
    Aes256,
}

/// Camellia key sizes.
#[cfg(feature = "camellia")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherCamelliaKeySize {
    Camellia128,
    Camellia192,
    Camellia256,
}

/// SM4 key sizes.
#[cfg(feature = "sm4")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherSm4KeySize {
    Sm4_128,
}

/// Indentify a symmetric block cipher algorithm together with a selected key
/// size.
///
/// For example `SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128)`
/// would identify "Aes128".
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymBlockCipherAlg {
    #[cfg(feature = "aes")]
    Aes(SymBlockCipherAesKeySize),
    #[cfg(feature = "camellia")]
    Camellia(SymBlockCipherCamelliaKeySize),
    #[cfg(feature = "sm4")]
    Sm4(SymBlockCipherSm4KeySize),
}

impl convert::From<&SymBlockCipherInstance> for SymBlockCipherAlg {
    /// Obtain the [symmetric block cipher algorithm
    /// identifier](SymBlockCipherAlg) associated with a
    /// [`SymBlockCipherInstance`].
    fn from(instance: &SymBlockCipherInstance) -> Self {
        match instance.state.deref() {
            #[cfg(feature = "aes")]
            SymBlockCipherInstanceState::Aes128(_) => Self::Aes(SymBlockCipherAesKeySize::Aes128),
            #[cfg(feature = "aes")]
            SymBlockCipherInstanceState::Aes192(_) => Self::Aes(SymBlockCipherAesKeySize::Aes192),
            #[cfg(feature = "aes")]
            SymBlockCipherInstanceState::Aes256(_) => Self::Aes(SymBlockCipherAesKeySize::Aes256),
            #[cfg(feature = "camellia")]
            SymBlockCipherInstanceState::Camellia128(_) => Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
            #[cfg(feature = "camellia")]
            SymBlockCipherInstanceState::Camellia192(_) => Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
            #[cfg(feature = "camellia")]
            SymBlockCipherInstanceState::Camellia256(_) => Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
            #[cfg(feature = "sm4")]
            SymBlockCipherInstanceState::Sm4_128(_) => Self::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
        }
    }
}

macro_rules! gen_match_on_block_cipher_alg {
    ($block_cipher_alg_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $block_cipher_alg_value {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(key_size) => {
                match key_size {
                    SymBlockCipherAesKeySize::Aes128 => {
                        $m!($($($args),*,)? Aes, 128)
                    },
                    SymBlockCipherAesKeySize::Aes192 => {
                        $m!($($($args),*,)? Aes, 192)
                    },
                    SymBlockCipherAesKeySize::Aes256 => {
                        $m!($($($args),*,)? Aes, 256)
                    },
                }
            },
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(key_size) => {
                match key_size {
                    SymBlockCipherCamelliaKeySize::Camellia128 => {
                        $m!($($($args),*,)? Camellia, 128)
                    },
                    SymBlockCipherCamelliaKeySize::Camellia192 => {
                        $m!($($($args),*,)? Camellia, 192)
                    },
                    SymBlockCipherCamelliaKeySize::Camellia256 => {
                        $m!($($($args),*,)? Camellia, 256)
                    },
                }
            },
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(key_size) => {
                match key_size {
                    SymBlockCipherSm4KeySize::Sm4_128 => {
                        $m!($($($args),*,)? Sm4, 128)
                    },
                }
            },
        }
    };
}

macro_rules! block_cipher_to_impl {
    (Aes, 128) => {
        aes::Aes128
    };
    (Aes, 192) => {
        aes::Aes192
    };
    (Aes, 256) => {
        aes::Aes256
    };
    (Camellia, 128) => {
        camellia::Camellia128
    };
    (Camellia, 192) => {
        camellia::Camellia192
    };
    (Camellia, 256) => {
        camellia::Camellia256
    };
    (Sm4, 128) => {
        sm4::Sm4
    };
}

macro_rules! gen_match_on_mode {
    ($mode_value:expr, $m:ident $(, $($args:tt),*)?) => {
        match $mode_value {
            #[cfg(feature = "ctr")]
            tpm2_interface::TpmiAlgCipherMode::Ctr => {
                $m!($($($args),*,)? Ctr)
            },
            #[cfg(feature = "ofb")]
            tpm2_interface::TpmiAlgCipherMode::Ofb => {
                $m!($($($args),*,)? Ofb)
            },
            #[cfg(feature = "cbc")]
            tpm2_interface::TpmiAlgCipherMode::Cbc => {
                $m!($($($args),*,)? Cbc)
            },
            #[cfg(feature = "cfb")]
            tpm2_interface::TpmiAlgCipherMode::Cfb => {
                $m!($($($args),*,)? Cfb)
            },
            #[cfg(feature = "ecb")]
            tpm2_interface::TpmiAlgCipherMode::Ecb => {
                $m!($($($args),*,)? Ecb)
            },
        }
    };
}

macro_rules! mode_to_enc_impl {
    (Ctr, $block_cipher_impl:ty) => {
        ctr_impl::Encryptor::<&$block_cipher_impl>
    };
    (Ofb, $block_cipher_impl:ty) => {
        ofb::OfbCore::<&$block_cipher_impl>
    };
    (Cbc, $block_cipher_impl:ty) => {
        cbc::Encryptor::<&$block_cipher_impl>
    };
    (Cfb, $block_cipher_impl:ty) => {
        cfb_mode::Encryptor::<&$block_cipher_impl>
    };
    (Ecb, $block_cipher_impl:ty) => {
        ecb::Encryptor::<&$block_cipher_impl>
    };
}

macro_rules! mode_to_dec_impl {
    (Ctr, $block_cipher_impl:ty) => {
        ctr_impl::Decryptor::<&$block_cipher_impl>
    };
    (Ofb, $block_cipher_impl:ty) => {
        ofb::OfbCore::<&$block_cipher_impl>
    };
    (Cbc, $block_cipher_impl:ty) => {
        cbc::Decryptor::<&$block_cipher_impl>
    };
    (Cfb, $block_cipher_impl:ty) => {
        cfb_mode::Decryptor::<&$block_cipher_impl>
    };
    (Ecb, $block_cipher_impl:ty) => {
        ecb::Decryptor::<&$block_cipher_impl>
    };
}

impl SymBlockCipherAlg {
    /// Determine the key length associated with the symmetric block cipher
    /// algorithm.
    pub fn key_len(&self) -> usize {
        macro_rules! gen_block_cipher_key_len {
            ($block_alg_id:ident,
             $key_size:tt) => {{
                let key_len = <block_cipher_to_impl!($block_alg_id, $key_size)>::key_size();
                debug_assert_eq!(8 * key_len, $key_size);
                key_len
            }};
        }
        gen_match_on_block_cipher_alg!(self, gen_block_cipher_key_len)
    }

    /// Determine the block length associated with the symmetric block cipher
    /// algorithm.
    pub fn block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($block_alg_id:ident,
             $key_size:tt) => {
                <block_cipher_to_impl!($block_alg_id, $key_size)>::block_size()
            };
        }
        gen_match_on_block_cipher_alg!(self, gen_block_cipher_block_len)
    }

    /// Determine the IV length for a [block cipher chaining
    /// mode](tpm2_interface::TpmiAlgCipherMode) operating on the symmetric
    /// block cipher algorithm.
    pub fn iv_len_for_mode(&self, mode: tpm2_interface::TpmiAlgCipherMode) -> usize {
        macro_rules! gen_iv_len_for_mode_and_block_cipher {
            (Ecb $(, $($args:tt),*)?) => {
                0
            };
            ($mode_id:tt,
              $block_alg_id:ident,
              $key_size:tt) => {
                <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::iv_size()
            };
        }

        gen_match_on_mode!(
            mode,
            gen_match_on_block_cipher_alg,
            self,
            gen_iv_len_for_mode_and_block_cipher
        )
    }
}

impl convert::TryFrom<(tpm2_interface::TpmiAlgSymObject, u16)> for SymBlockCipherAlg {
    type Error = CryptoError;

    /// Convert a pair of [TCG block cipher algorithm
    /// identifier](tpm2_interface::TpmiAlgSymObject) and key size to
    /// a [symmetric block cipher algorithm identifier](SymBlockCipherAlg).
    fn try_from(value: (tpm2_interface::TpmiAlgSymObject, u16)) -> Result<Self, Self::Error> {
        let (block_alg, key_size) = value;

        match block_alg {
            #[cfg(feature = "aes")]
            tpm2_interface::TpmiAlgSymObject::Aes => match key_size {
                128 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes128)),
                192 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes192)),
                256 => Ok(Self::Aes(SymBlockCipherAesKeySize::Aes256)),
                _ => Err(CryptoError::InvalidParams),
            },
            #[cfg(feature = "camellia")]
            tpm2_interface::TpmiAlgSymObject::Camellia => match key_size {
                128 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia128)),
                192 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia192)),
                256 => Ok(Self::Camellia(SymBlockCipherCamelliaKeySize::Camellia256)),
                _ => Err(CryptoError::InvalidParams),
            },
            #[cfg(feature = "sm4")]
            tpm2_interface::TpmiAlgSymObject::Sm4 => match key_size {
                128 => Ok(Self::Sm4(SymBlockCipherSm4KeySize::Sm4_128)),
                _ => Err(CryptoError::InvalidParams),
            },
        }
    }
}

impl convert::From<&SymBlockCipherAlg> for (tpm2_interface::TpmiAlgSymObject, u16) {
    /// Convert a [symmetric block cipher algorithm
    /// identifier](SymBlockCipherAlg) into a pair of [TCG block cipher
    /// algorithm identifier](tpm2_interface::TpmiAlgSymObject) and key size.
    fn from(value: &SymBlockCipherAlg) -> Self {
        match value {
            #[cfg(feature = "aes")]
            SymBlockCipherAlg::Aes(key_size) => (
                tpm2_interface::TpmiAlgSymObject::Aes,
                match key_size {
                    SymBlockCipherAesKeySize::Aes128 => 128,
                    SymBlockCipherAesKeySize::Aes192 => 192,
                    SymBlockCipherAesKeySize::Aes256 => 256,
                },
            ),
            #[cfg(feature = "camellia")]
            SymBlockCipherAlg::Camellia(key_size) => (
                tpm2_interface::TpmiAlgSymObject::Camellia,
                match key_size {
                    SymBlockCipherCamelliaKeySize::Camellia128 => 128,
                    SymBlockCipherCamelliaKeySize::Camellia192 => 192,
                    SymBlockCipherCamelliaKeySize::Camellia256 => 256,
                },
            ),
            #[cfg(feature = "sm4")]
            SymBlockCipherAlg::Sm4(key_size) => (
                tpm2_interface::TpmiAlgSymObject::Sm4,
                match key_size {
                    SymBlockCipherSm4KeySize::Sm4_128 => 128,
                },
            ),
        }
    }
}

/// A symmetric block cipher key.
///
/// Associate the raw key material with a [symmetric block cipher algorithm
/// identifier](SymBlockCipherAlg).
///
/// May get instantiate either through [key generation](Self::generate) or from
/// an existing raw key via [`TryFrom`].
pub struct SymBlockCipherKey {
    block_cipher_alg: SymBlockCipherAlg,
    key: zeroize::Zeroizing<Vec<u8>>,
}

impl SymBlockCipherKey {
    /// Get the key's associated [symmetric block cipher algorithm
    /// identifier](SymBlockCipherAlg).
    pub fn get_block_cipher_alg(&self) -> SymBlockCipherAlg {
        self.block_cipher_alg
    }

    /// Take the key.
    pub fn take_key(self) -> zeroize::Zeroizing<Vec<u8>> {
        let Self {
            block_cipher_alg: _,
            key,
        } = self;
        key
    }

    /// Generate a new block cipher key.
    ///
    /// # Arguments:
    /// * `block_cipher_alg` - The block cipher algorithm to generate a key for.
    /// * `rng` - The random number generator to obtain key material from.
    /// * `additional_rng_generate_input` - Additional input to pass along to
    ///   the `rng`'s [generate()](rng::RngCore::generate) primitive.
    pub fn generate(
        block_cipher_alg: SymBlockCipherAlg,
        rng: &mut dyn rng::RngCoreDispatchable,
        additional_rng_generate_input: Option<&[Option<&[u8]>]>,
    ) -> Result<Self, CryptoError> {
        let mut key = try_alloc_zeroizing_vec(block_cipher_alg.key_len())?;
        rng::rng_dyn_dispatch_generate(
            rng,
            io_slices::SingletonIoSliceMut::new(&mut key).map_infallible_err(),
            additional_rng_generate_input,
        )?;
        Ok(Self { block_cipher_alg, key })
    }

    /// Instantiate a block cipher instance for the key.
    pub fn instantiate_block_cipher(&self) -> Result<SymBlockCipherInstance, CryptoError> {
        SymBlockCipherInstance::new(self.block_cipher_alg, &self.key)
    }
}

impl convert::TryFrom<(SymBlockCipherAlg, &[u8])> for SymBlockCipherKey {
    type Error = CryptoError;

    /// Construct a [`SymBlockCipherKey`] from a pair of [symmetric block cipher
    /// algorithm identifier](SymBlockCipherAlg) and a raw key byte slice.
    fn try_from(value: (SymBlockCipherAlg, &[u8])) -> Result<Self, Self::Error> {
        let (block_cipher_alg, supplied_key) = value;

        if supplied_key.len() != block_cipher_alg.key_len() {
            return Err(CryptoError::KeySize);
        }

        let mut key = try_alloc_zeroizing_vec::<u8>(block_cipher_alg.key_len())?;
        key.copy_from_slice(supplied_key);

        Ok(Self { block_cipher_alg, key })
    }
}

impl convert::TryFrom<(SymBlockCipherAlg, zeroize::Zeroizing<Vec<u8>>)> for SymBlockCipherKey {
    type Error = CryptoError;

    /// Destructure a [`SymBlockCipherKey`] into a pair of [symmetric block
    /// cipher algorithm identifier](SymBlockCipherAlg) and a raw key byte
    /// `Vec`.
    fn try_from(value: (SymBlockCipherAlg, zeroize::Zeroizing<Vec<u8>>)) -> Result<Self, Self::Error> {
        let (block_cipher_alg, supplied_key) = value;

        if supplied_key.len() != block_cipher_alg.key_len() {
            return Err(CryptoError::KeySize);
        }

        Ok(Self {
            block_cipher_alg,
            key: supplied_key,
        })
    }
}

impl zeroize::ZeroizeOnDrop for SymBlockCipherKey {}

/// A symmetric block cipher instance providing encryption and decryption
/// functionality.
///
/// A symmetric block cipher instance is associated with a specific [block
/// cipher algorithm](SymBlockCipherAlg) and a key.  It may get instantiated
/// either [directly from a raw key byte slice](Self::new) or from a
/// [`SymBlockCipherKey`](SymBlockCipherKey::instantiate_block_cipher).
///
/// Encryption and decryption requests are handled through
/// [`encrypt()`](Self::encrypt)/[`encrypt_in_place()`](Self::encrypt_in_place)
/// and [`decrypt()`](Self::decrypt)/
/// [`decrypt_in_place()`](Self::decrypt_in_place) respectively. These
/// all accept a [block cipher chaining mode](tpm2_interface::TpmiAlgCipherMode)
/// to be used for the request. Encryption and decryption operations don't alter
/// the instance's state and a single instance may be used for the encrpytion or
/// decryption of multiple independent message.
pub struct SymBlockCipherInstance {
    state: Box<SymBlockCipherInstanceState>,
}

impl SymBlockCipherInstance {
    /// Instantiate a `SymBlockCipherInstance` from a pair of [symmetric block
    /// cipher algorithm identifier](SymBlockCipherAlg) and a raw key byte
    /// slice.
    ///
    /// # Arguments:
    /// * `alg_id` - The [symmetric block cipher algorithm](SymBlockCipherAlg)
    ///   to be used for this instance.
    /// * `key` - The raw key bytes. It's length must match the [expected key
    ///   length](SymBlockCipherAlg::key_len) for `alg` or an error will get
    ///   returned.
    #[inline(never)]
    pub fn new(alg_id: SymBlockCipherAlg, key: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            state: SymBlockCipherInstanceState::new(alg_id, key)?,
        })
    }

    /// Try to clone a `SymBlockCipherInstance`.
    #[inline(never)]
    pub fn try_clone(&self) -> Result<Self, CryptoError> {
        Ok(Self {
            state: box_try_new_with(|| -> Result<SymBlockCipherInstanceState, convert::Infallible> {
                Ok(self.state.deref().clone())
            })?,
        })
    }

    /// Obtain the instance's associated block cipher algorithm's block length.
    ///
    /// Equivalent to
    /// [`SymBlockCipherAlg::block_len()`](SymBlockCipherAlg::block_len).
    pub fn block_len(&self) -> usize {
        self.state.block_len()
    }

    /// Determine the IV length for the use of the `SymBlockCipherInstance` with
    /// a given [block cipher chaining mode](tpm2_interface::TpmiAlgCipherMode).
    ///
    /// Equivalent to
    /// [`SymBlockCipherAlg::iv_len_for_mode()`](SymBlockCipherAlg::iv_len_for_mode).
    pub fn iv_len_for_mode(&self, mode: tpm2_interface::TpmiAlgCipherMode) -> usize {
        self.state.iv_len_for_mode(mode)
    }

    /// Encrypt with a specified [block cipher chaining
    /// mode](tpm2_interface::TpmiAlgCipherMode).
    ///
    /// The source and destination buffers must be equal in length or an error
    /// will get returned. Depending on the `mode`, their lengths must
    /// perhaps be aligned to the [block cipher block
    /// length](Self::block_len), an error will get returned otherwise.
    ///
    /// # Arguments:
    /// * `mode` - The [block cipher chaining
    ///   mode](tpm2_interface::TpmiAlgCipherMode) to use.
    /// * `iv` - The IV to use for the `mode`. Its length must match the
    ///   expected [IV length](Self::iv_len_for_mode) for the given combination
    ///   of the instance's associated block cipher algorithm and the specified
    ///   `mode`.
    /// * `dst` - The destination buffers to write the encrypted message to.
    /// * `src` - The source buffers holding the cleartext message to encrypt.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher chaining `mode`.
    pub fn encrypt<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        mut dst: DI,
        mut src: SI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.encrypt(mode, iv, &mut dst, &mut src, iv_out)
    }

    /// Encrypt in place with a specified [block cipher chaining
    /// mode](tpm2_interface::TpmiAlgCipherMode).
    ///
    /// Depending on the `mode`, the source/destination buffer's length must
    /// perhaps be aligned to the [block cipher block
    /// length](Self::block_len), an error will get returned otherwise.
    ///
    /// <div class="warning">
    ///
    /// Unlike it's the case with [`encrypt()`](Self::encrypt), the
    /// source/destination buffer's generic `DI` type is not `dyn`
    /// compatible. The compiler will emit a separate instance for each
    /// individual `DI` `encrypt_in_place()` gets invoked with. Be vigilant
    /// of template bloat, prefer [`encrypt()`](Self::encrypt) if feasible and
    /// try to not use too exotic types for `DI` here otherwise.
    ///
    /// </div>
    ///
    /// # Arguments:
    /// * `mode` - The [block cipher chaining
    ///   mode](tpm2_interface::TpmiAlgCipherMode) to use.
    /// * `iv` - The IV to use for the `mode`. Its length must match the
    ///   expected [IV length](Self::iv_len_for_mode) for the given combination
    ///   of the instance's associated block cipher algorithm and the specified
    ///   `mode`.
    /// * `dst` - The source/destination buffers initially holding the cleartext
    ///   message and receiving the encrypted result.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher chaining `mode`.
    pub fn encrypt_in_place<'a, 'b, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.encrypt_in_place(mode, iv, dst, iv_out)
    }

    /// Decrypt with a specified [block cipher chaining
    /// mode](tpm2_interface::TpmiAlgCipherMode).
    ///
    /// The source and destination buffers must be equal in length or an error
    /// will get returned. Depending on the `mode`, their lengths must
    /// perhaps be aligned to the [block cipher block
    /// length](Self::block_len), an error will get returned otherwise.
    ///
    /// # Arguments:
    /// * `mode` - The [block cipher chaining
    ///   mode](tpm2_interface::TpmiAlgCipherMode) to use.
    /// * `iv` - The IV to use for the `mode`. Its length must match the
    ///   expected [IV length](Self::iv_len_for_mode) for the given combination
    ///   of the instance's associated block cipher algorithm and the specified
    ///   `mode`.
    /// * `dst` - The destination buffers to write the decrypted message to.
    /// * `src` - The source buffers holding the encrypted message to decrypt.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher chaining `mode`.
    pub fn decrypt<'a, 'b, DI: CryptoWalkableIoSlicesMutIter<'a>, SI: CryptoWalkableIoSlicesIter<'b>>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        mut dst: DI,
        mut src: SI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.decrypt(mode, iv, &mut dst, &mut src, iv_out)
    }

    /// Decrypt in place with a specified [block cipher chaining
    /// mode](tpm2_interface::TpmiAlgCipherMode).
    ///
    /// Depending on the `mode`, the source/destination buffer's length must
    /// perhaps be aligned to the [block cipher block
    /// length](Self::block_len), an error will get returned otherwise.
    ///
    /// <div class="warning">
    ///
    /// Unlike it's the case with [`decrypt()`](Self::decrypt), the
    /// source/destination buffer's generic `DI` type is not `dyn`
    /// compatible. The compiler will emit a separate instance for each
    /// individual `DI` `decrypt_in_place()` gets invoked with. Be vigilant
    /// of template bloat, prefer [`decrypt()`](Self::encrypt) if feasible and
    /// try to not use too exotic types for `DI` here otherwise.
    ///
    /// </div>
    ///
    /// # Arguments:
    /// * `mode` - The [block cipher chaining
    ///   mode](tpm2_interface::TpmiAlgCipherMode) to use.
    /// * `iv` - The IV to use for the `mode`. Its length must match the
    ///   expected [IV length](Self::iv_len_for_mode) for the given combination
    ///   of the instance's associated block cipher algorithm and the specified
    ///   `mode`.
    /// * `dst` - The source/destination buffers initially holding the encrypted
    ///   message and receiving the decrypted result.
    /// * `iv_out` - Optional buffer receiving the final IV as ouput from the
    ///   block cipher chaining `mode`.
    pub fn decrypt_in_place<'a, 'b, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        self.state.decrypt_in_place(mode, iv, dst, iv_out)
    }
}

// All supported block cipher implementations possibly wrapped implement
// ZeroizeOnDrop.
#[cfg(feature = "zeroize")]
impl zeroize::ZeroizeOnDrop for SymBlockCipherInstance {}

#[derive(Clone)]
enum SymBlockCipherInstanceState {
    #[cfg(feature = "aes")]
    Aes128(block_cipher_to_impl!(Aes, 128)),
    #[cfg(feature = "aes")]
    Aes192(block_cipher_to_impl!(Aes, 192)),
    #[cfg(feature = "aes")]
    Aes256(block_cipher_to_impl!(Aes, 256)),
    #[cfg(feature = "camellia")]
    Camellia128(block_cipher_to_impl!(Camellia, 128)),
    #[cfg(feature = "camellia")]
    Camellia192(block_cipher_to_impl!(Camellia, 192)),
    #[cfg(feature = "camellia")]
    Camellia256(block_cipher_to_impl!(Camellia, 256)),
    #[cfg(feature = "sm4")]
    Sm4_128(block_cipher_to_impl!(Sm4, 128)),
}

macro_rules! gen_match_on_block_cipher_instance {
    ($block_cipher_instance_value:expr, $m:ident, $block_cipher_impl_instance:ident $(, $($args:tt),*)?) => {
        match $block_cipher_instance_value {
            #[cfg(feature = "aes")]
            SymBlockCipherInstanceState::Aes128($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Aes, 128, $block_cipher_impl_instance)
            },
            #[cfg(feature = "aes")]
            SymBlockCipherInstanceState::Aes192($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Aes, 192, $block_cipher_impl_instance)
            },
            #[cfg(feature = "aes")]
            SymBlockCipherInstanceState::Aes256($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Aes, 256, $block_cipher_impl_instance)
            },
            #[cfg(feature = "camellia")]
            SymBlockCipherInstanceState::Camellia128($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Camellia, 128, $block_cipher_impl_instance)
            },
            #[cfg(feature = "camellia")]
            SymBlockCipherInstanceState::Camellia192($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Camellia, 192, $block_cipher_impl_instance)
            },
            #[cfg(feature = "camellia")]
            SymBlockCipherInstanceState::Camellia256($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Camellia, 256, $block_cipher_impl_instance)
            },
            #[cfg(feature = "sm4")]
            SymBlockCipherInstanceState::Sm4_128($block_cipher_impl_instance) => {
                $m!($($($args),*,)? Sm4, 128, $block_cipher_impl_instance)
            },
        }
    };
}

macro_rules! block_alg_id_to_instance_variant {
    (Aes, 128) => {
        SymBlockCipherInstanceState::Aes128
    };
    (Aes, 192) => {
        SymBlockCipherInstanceState::Aes192
    };
    (Aes, 256) => {
        SymBlockCipherInstanceState::Aes256
    };
    (Camellia, 128) => {
        SymBlockCipherInstanceState::Camellia128
    };
    (Camellia, 192) => {
        SymBlockCipherInstanceState::Camellia192
    };
    (Camellia, 256) => {
        SymBlockCipherInstanceState::Camellia256
    };
    (Sm4, 128) => {
        SymBlockCipherInstanceState::Sm4_128
    };
}

// Used internally from multiple functions of SymBlockCipherInstanceState. We
// cannot have macro definitions in impl {} blocks, so it's here.
macro_rules! sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher {
    ($mode_id:tt, $mode_supports_partial_last_block:literal, $gen_mode_transform_new_impl_instance_snippet:ident,
             $gen_mode_block_transform_cb_snippet:ident,
             $gen_mode_transform_grab_iv_snippet:ident,
             $dst_io_slices:ident,
             $src_io_slices:ident,
             $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
        let block_len = <block_cipher_to_impl!($block_alg_id, $key_size)>::block_size();
        let dst_len = $dst_io_slices.total_len()?;
        if !$mode_supports_partial_last_block && dst_len % block_len != 0 {
            return Err(CryptoError::InvalidMessageLength);
        } else if $src_io_slices.total_len()? != dst_len {
            return Err(CryptoError::Internal);
        }

        let mut scratch_block_buf = zeroize::Zeroizing::from(Vec::new());
        if !$dst_io_slices.all_aligned_to(block_len)? || !$src_io_slices.all_aligned_to(block_len)? {
            scratch_block_buf = try_alloc_zeroizing_vec(block_len)?;
        }

        let mut mode_transform_impl_instance = $gen_mode_transform_new_impl_instance_snippet!(
            $mode_id,
            $block_alg_id,
            $key_size,
            $block_cipher_impl_instance
        );

        loop {
            if !Self::transform_next_blocks::<$mode_supports_partial_last_block, _>(
                $dst_io_slices,
                $src_io_slices,
                $gen_mode_block_transform_cb_snippet!(mode_transform_impl_instance),
                block_len,
                &mut scratch_block_buf,
            )? {
                break;
            }
        }

        $gen_mode_transform_grab_iv_snippet!(mode_transform_impl_instance);
    }};
}

// Used internally from multiple functions of SymBlockCipherInstanceState. We
// cannot have macro definitions in impl {} blocks, so it's here.
macro_rules! sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher {
    ($mode_id:tt, $mode_supports_partial_last_block:literal, $gen_mode_transform_new_impl_instance_snippet:ident,
             $gen_mode_block_transform_cb_snippet:ident,
             $gen_mode_transform_grab_iv_snippet:ident,
             $dst_io_slices:ident,
             $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
        let block_len = <block_cipher_to_impl!($block_alg_id, $key_size)>::block_size();
        let dst_len = $dst_io_slices.total_len()?;
        if !$mode_supports_partial_last_block && dst_len % block_len != 0 {
            return Err(CryptoError::InvalidMessageLength);
        }

        let mut scratch_block_buf = zeroize::Zeroizing::from(Vec::new());
        if !$dst_io_slices.all_aligned_to(block_len)? {
            scratch_block_buf = try_alloc_zeroizing_vec(block_len)?;
        }

        let mut mode_transform_impl_instance = $gen_mode_transform_new_impl_instance_snippet!(
            $mode_id,
            $block_alg_id,
            $key_size,
            $block_cipher_impl_instance
        );

        loop {
            if !Self::transform_next_blocks_in_place::<$mode_supports_partial_last_block, _, _>(
                &mut $dst_io_slices,
                $gen_mode_block_transform_cb_snippet!(mode_transform_impl_instance),
                block_len,
                &mut scratch_block_buf,
            )? {
                break;
            }
        }

        $gen_mode_transform_grab_iv_snippet!(mode_transform_impl_instance);
    }};
}

impl SymBlockCipherInstanceState {
    fn new(alg_id: SymBlockCipherAlg, key: &[u8]) -> Result<Box<Self>, CryptoError> {
        macro_rules! gen_block_alg_instantiate {
            ($block_alg_id:tt, $key_size:tt) => {{
                // Don't use crypto_common's convenience KeyInit::from_slice() for instantiating the
                // cipher, but wrap the key explictly first to have all possible error paths out of
                // the way, thereby enabling a zero copy construction right into the Box' memory.
                if key.len() !=
                                <block_cipher_to_impl!($block_alg_id, $key_size) as crypto_common::KeySizeUser>
                                    ::KeySize::to_usize() {
                                return Err(CryptoError::KeySize);
                            }
                let key = crypto_common::Key::<block_cipher_to_impl!($block_alg_id, $key_size)>::from_slice(key);

                box_try_new_with(|| -> Result<Self, convert::Infallible> {
                    Ok(block_alg_id_to_instance_variant!($block_alg_id, $key_size)(
                        <block_cipher_to_impl!($block_alg_id, $key_size)>::new(key),
                    ))
                })?
            }};
        }

        Ok(gen_match_on_block_cipher_alg!(alg_id, gen_block_alg_instantiate))
    }

    fn transform_next_blocks<'a, 'b, const ENABLE_PARTIAL_LAST_BLOCK: bool, BT: FnMut(&mut [u8], Option<&[u8]>)>(
        dst: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        src: &mut dyn CryptoWalkableIoSlicesIter<'b>,
        mut block_transform: BT,
        block_len: usize,
        scratch_block_buf: &mut [u8],
    ) -> Result<bool, CryptoError> {
        debug_assert!(ENABLE_PARTIAL_LAST_BLOCK || dst.is_empty()? || dst.total_len()? >= block_len);
        debug_assert_eq!(src.total_len()?, dst.total_len()?);
        let first_dst_slice_len = dst.next_slice_len()?;
        // Try to process a batch of multiple block cipher blocks at once.
        if first_dst_slice_len >= 2 * block_len {
            let first_src_slice_len = src.next_slice_len()?;
            if first_src_slice_len >= 2 * block_len {
                let batch_len = first_dst_slice_len.min(first_src_slice_len);
                let batch_len = if block_len.is_pow2() {
                    batch_len & !(block_len - 1)
                } else {
                    batch_len - (batch_len % block_len)
                };
                let batch_dst_slice = match dst.next_slice_mut(Some(batch_len))? {
                    Some(batch_dst_slice) => batch_dst_slice,
                    None => return Err(CryptoError::Internal),
                };
                let batch_src_slice = match src.next_slice(Some(batch_len))? {
                    Some(batch_src_slice) => batch_src_slice,
                    None => return Err(CryptoError::Internal),
                };

                let mut pos_in_batch_slice = 0;
                while pos_in_batch_slice != batch_len {
                    block_transform(
                        &mut batch_dst_slice[pos_in_batch_slice..pos_in_batch_slice + block_len],
                        Some(&batch_src_slice[pos_in_batch_slice..pos_in_batch_slice + block_len]),
                    );
                    pos_in_batch_slice += block_len
                }
                return Ok(true);
            }
        }

        let first_dst_slice = match dst.next_slice_mut(Some(block_len))? {
            Some(first_dst_slice) => first_dst_slice,
            None => {
                if !src.is_empty()? {
                    return Err(CryptoError::Internal);
                }
                return Ok(false);
            }
        };
        let first_src_slice = match src.next_slice(Some(block_len))? {
            Some(first_src_slice) => first_src_slice,
            None => return Err(CryptoError::Internal),
        };
        if first_src_slice.len() == block_len && first_dst_slice.len() == block_len {
            block_transform(first_dst_slice, Some(first_src_slice));
        } else {
            debug_assert_eq!(scratch_block_buf.len(), block_len);
            let mut src_block_len = first_src_slice.len();
            scratch_block_buf[..src_block_len].copy_from_slice(first_src_slice);
            src_block_len += io_slices::SingletonIoSliceMut::new(&mut scratch_block_buf[src_block_len..])
                .map_infallible_err::<CryptoError>()
                .copy_from_iter(src)?;
            if src_block_len != block_len {
                if !ENABLE_PARTIAL_LAST_BLOCK {
                    return Err(CryptoError::Internal);
                } else {
                    scratch_block_buf[src_block_len..].fill(0);
                }
            } else if src_block_len < first_dst_slice.len() {
                return Err(CryptoError::Internal);
            }

            block_transform(scratch_block_buf, None);

            let mut dst_block_len = first_dst_slice.len();
            first_dst_slice.copy_from_slice(&scratch_block_buf[..dst_block_len]);
            dst_block_len += dst.copy_from_iter(
                &mut io_slices::SingletonIoSlice::new(&scratch_block_buf[dst_block_len..src_block_len])
                    .map_infallible_err(),
            )?;
            if dst_block_len != src_block_len {
                return Err(CryptoError::Internal);
            }
        }

        Ok(true)
    }

    fn transform_next_blocks_in_place<
        'a,
        'b,
        const ENABLE_PARTIAL_LAST_BLOCK: bool,
        BT: FnMut(&mut [u8], Option<&[u8]>),
        DI: CryptoPeekableIoSlicesMutIter<'a>,
    >(
        dst: &mut DI,
        mut block_transform: BT,
        block_len: usize,
        scratch_block_buf: &mut [u8],
    ) -> Result<bool, CryptoError> {
        debug_assert!(ENABLE_PARTIAL_LAST_BLOCK || dst.is_empty()? || dst.total_len()? >= block_len);
        let first_dst_slice_len = dst.next_slice_len()?;
        // Try to process a batch of multiple block cipher blocks at once.
        if first_dst_slice_len >= 2 * block_len {
            let batch_len = if block_len.is_pow2() {
                first_dst_slice_len & !(block_len - 1)
            } else {
                first_dst_slice_len - (first_dst_slice_len % block_len)
            };
            let batch_dst_slice = match dst.next_slice_mut(Some(batch_len))? {
                Some(batch_dst_slice) => batch_dst_slice,
                None => return Err(CryptoError::Internal),
            };

            let mut pos_in_batch_slice = 0;
            while pos_in_batch_slice != batch_len {
                block_transform(
                    &mut batch_dst_slice[pos_in_batch_slice..pos_in_batch_slice + block_len],
                    None,
                );
                pos_in_batch_slice += block_len
            }
            return Ok(true);
        }

        let first_dst_slice = match dst.next_slice_mut(Some(block_len))? {
            Some(first_dst_slice) => first_dst_slice,
            None => {
                return Ok(false);
            }
        };
        if first_dst_slice.len() == block_len {
            block_transform(first_dst_slice, None);
        } else {
            debug_assert_eq!(scratch_block_buf.len(), block_len);
            let mut src_block_len = first_dst_slice.len();
            scratch_block_buf[..src_block_len].copy_from_slice(first_dst_slice);
            // When copying from the destination into the scratch buffer, retain the
            // original IOSlicesMut, so that the result can later get written back again.
            src_block_len += io_slices::SingletonIoSliceMut::new(&mut scratch_block_buf[src_block_len..])
                .map_infallible_err()
                .copy_from_iter(&mut dst.decoupled_borrow())?;
            if src_block_len != block_len {
                if !ENABLE_PARTIAL_LAST_BLOCK {
                    return Err(CryptoError::Internal);
                } else {
                    scratch_block_buf[src_block_len..].fill(0);
                }
            }

            block_transform(scratch_block_buf, None);

            let mut dst_block_len = first_dst_slice.len();
            first_dst_slice.copy_from_slice(&scratch_block_buf[..dst_block_len]);
            dst_block_len += dst.copy_from_iter(
                &mut io_slices::SingletonIoSlice::new(&scratch_block_buf[dst_block_len..]).map_infallible_err(),
            )?;
            debug_assert_eq!(dst_block_len, src_block_len);
        }

        Ok(true)
    }

    fn block_len(&self) -> usize {
        macro_rules! gen_block_cipher_block_len {
            ($block_alg_id:ident,
             $key_size:tt,
             _unused) => {
                <block_cipher_to_impl!($block_alg_id, $key_size)>::block_size()
            };
        }
        gen_match_on_block_cipher_instance!(self, gen_block_cipher_block_len, _unused)
    }

    fn iv_len_for_mode(&self, mode: tpm2_interface::TpmiAlgCipherMode) -> usize {
        macro_rules! gen_iv_len_for_mode_and_block_cipher {
            (Ecb $(, $($args:tt),*)?) => {
                0
            };
            ($mode_id:tt,
              $block_alg_id:ident,
              $key_size:tt,
              _unused) => {
                <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::iv_size()
            };
        }

        gen_match_on_mode!(
            mode,
            gen_match_on_block_cipher_instance,
            self,
            gen_iv_len_for_mode_and_block_cipher,
            _unused
        )
    }

    #[inline(never)]
    fn encrypt<'a, 'b>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        dst: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        src: &mut dyn CryptoWalkableIoSlicesIter<'b>,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerIvInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                // Don't use crypto_common's convenience InnerIvInit::from_slice() for
                // instantiating the block mode, but wrap the IV explictly first to have
                // all possible error paths out of the way, thereby enabling a zero copy
                // construction right onto the stack.
                let iv_len = <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))
                                                                                     as crypto_common::IvSizeUser>
                                                                                 ::IvSize::to_usize();
                if iv.len() != iv_len {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(CryptoError::Internal);
                    }
                }

                let iv = crypto_common::Iv::<
                    mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size)),
                >::from_slice(iv);

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockEncrypt, hence BlockEncryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_iv_init(
                    $block_cipher_impl_instance,
                    iv,
                )
            }};
        }

        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_init_trait_mode_encryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                if iv.len() != 0 {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(CryptoError::Internal);
                    }
                }

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockEncrypt, hence BlockEncryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_init(
                    $block_cipher_impl_instance,
                )
            }};
        }

        // Generate code snippet for the block transform callback passed to
        // Self::transform_next_blocks() for (external) mode implementations
        // implementing the cipher::BlockEncryptMut trait.
        macro_rules! gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_block: &mut [u8], src_block: Option<&[u8]>| {
                    if let Some(src_block) = src_block {
                        $mode_transform_impl_instance.encrypt_block_b2b_mut(src_block.into(), dst_block.into());
                    } else {
                        $mode_transform_impl_instance.encrypt_block_mut(dst_block.into());
                    }
                }
            };
        }

        // Generate code snippet for obtaining the IV from for (external) mode
        // implementations implementing the cipher::IvState trait.
        #[allow(unused_macros)]
        macro_rules! gen_iv_state_trait_mode_grab_iv_snippet {
            ($mode_transform_impl_instance:ident) => {{
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice($mode_transform_impl_instance.iv_state().deref());
                }
            }};
        }

        // Generate nop code snippet for obtaining the IV from modes with no IV.
        #[allow(unused_macros)]
        macro_rules! gen_grab_iv_nop_snippet {
            ($mode_transform_impl_instance:ident) => {};
        }

        macro_rules! gen_encrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ctr,
                    true,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ofb,
                    true,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cbc,
                    false,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cfb,
                    true,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ecb,
                    false,
                    gen_inner_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_grab_iv_nop_snippet,
                    dst,
                    src
                )
            };
        }

        gen_match_on_mode!(mode, gen_encrypt_with_mode);

        Ok(())
    }

    fn encrypt_in_place<'a, 'b, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        mut dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerIvInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                // Don't use crypto_common's convenience InnerIvInit::from_slice() for
                // instantiating the block mode, but wrap the IV explictly first to have
                // all possible error paths out of the way, thereby enabling a zero copy
                // construction right onto the stack.
                let iv_len = <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))
                                                                                     as crypto_common::IvSizeUser>
                                                                                 ::IvSize::to_usize();
                if iv.len() != iv_len {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(CryptoError::Internal);
                    }
                }

                let iv = crypto_common::Iv::<
                    mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size)),
                >::from_slice(iv);

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockEncrypt, hence BlockEncryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_iv_init(
                    $block_cipher_impl_instance,
                    iv,
                )
            }};
        }

        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_init_trait_mode_encryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                if iv.len() != 0 {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(CryptoError::Internal);
                    }
                }

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockEncrypt, hence BlockEncryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_enc_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_init(
                    $block_cipher_impl_instance,
                )
            }};
        }

        // Generate code snippet for the block transform callback passed to
        // Self::transform_next_blocks_in_place() for (external) mode implementations
        // implementing the cipher::BlockEncryptMut trait.
        macro_rules! gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_block: &mut [u8], src_block: Option<&[u8]>| {
                    if let Some(src_block) = src_block {
                        $mode_transform_impl_instance.encrypt_block_b2b_mut(src_block.into(), dst_block.into());
                    } else {
                        $mode_transform_impl_instance.encrypt_block_mut(dst_block.into());
                    }
                }
            };
        }

        // Generate code snippet for obtaining the IV from for (external) mode
        // implementations implementing the cipher::IvState trait.
        #[allow(unused_macros)]
        macro_rules! gen_iv_state_trait_mode_grab_iv_snippet {
            ($mode_transform_impl_instance:ident) => {{
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice($mode_transform_impl_instance.iv_state().deref());
                }
            }};
        }

        // Generate nop code snippet for obtaining the IV from modes with no IV.
        #[allow(unused_macros)]
        macro_rules! gen_grab_iv_nop_snippet {
            ($mode_transform_impl_instance:ident) => {};
        }

        macro_rules! gen_encrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ctr,
                    true,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ofb,
                    true,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cbc,
                    false,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cfb,
                    true,
                    gen_inner_iv_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ecb,
                    false,
                    gen_inner_init_trait_mode_encryptor_impl_instance_new_snippet,
                    gen_block_encrypt_trait_mode_block_encrypt_transform_cb_snippet,
                    gen_grab_iv_nop_snippet,
                    dst
                )
            };
        }

        gen_match_on_mode!(mode, gen_encrypt_with_mode);

        Ok(())
    }

    #[inline(never)]
    fn decrypt<'a, 'b>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        dst: &mut dyn CryptoWalkableIoSlicesMutIter<'a>,
        src: &mut dyn CryptoWalkableIoSlicesIter<'b>,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerIvInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                // Don't use the convenience InnerIvInit::from_slice() for instantiating the
                // block mode, but wrap the IV explictly first to have all possible
                // error paths out of the way, thereby enabling a zero copy construction
                // right onto the stack.
                let iv_len = <mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))
                                                                                     as crypto_common::IvSizeUser>
                                                                                 ::IvSize::to_usize();
                if iv.len() != iv_len {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(CryptoError::Internal);
                    }
                }

                let iv = crypto_common::Iv::<
                    mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size)),
                >::from_slice(iv);

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockDecrypt, hence BlockDecryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_iv_init(
                    &$block_cipher_impl_instance,
                    iv,
                )
            }};
        }

        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_init_trait_mode_decryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                if iv.len() != 0 {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(CryptoError::Internal);
                    }
                }

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockDecrypt, hence BlockDecryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_init(
                    $block_cipher_impl_instance,
                )
            }};
        }

        // Generate code snippet for the block transform callback passed to
        // Self::transform_next_blocks() for (external) mode implementations
        // implementing the cipher::BlockDecryptMut trait.
        macro_rules! gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_block: &mut [u8], src_block: Option<&[u8]>| {
                    if let Some(src_block) = src_block {
                        $mode_transform_impl_instance.decrypt_block_b2b_mut(src_block.into(), dst_block.into());
                    } else {
                        $mode_transform_impl_instance.decrypt_block_mut(dst_block.into());
                    }
                }
            };
        }

        // Generate code snippet for obtaining the IV from for (external) mode
        // implementations implementing the cipher::IvState trait.
        #[allow(unused_macros)]
        macro_rules! gen_iv_state_trait_mode_grab_iv_snippet {
            ($mode_transform_impl_instance:ident) => {{
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice($mode_transform_impl_instance.iv_state().deref());
                }
            }};
        }

        // Generate nop code snippet for obtaining the IV from modes with no IV.
        #[allow(unused_macros)]
        macro_rules! gen_grab_iv_nop_snippet {
            ($mode_transform_impl_instance:ident) => {};
        }

        macro_rules! gen_decrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ctr,
                    true,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ofb,
                    true,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cbc,
                    false,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cfb,
                    true,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst,
                    src
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ecb,
                    false,
                    gen_inner_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_grab_iv_nop_snippet,
                    dst,
                    src
                )
            };
        }

        gen_match_on_mode!(mode, gen_decrypt_with_mode);

        Ok(())
    }

    fn decrypt_in_place<'a, 'b, DI: CryptoPeekableIoSlicesMutIter<'a>>(
        &self,
        mode: tpm2_interface::TpmiAlgCipherMode,
        iv: &[u8],
        mut dst: DI,
        iv_out: Option<&mut [u8]>,
    ) -> Result<(), CryptoError> {
        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerIvInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                // Don't use crypto_common's convenience InnerIvInit::from_slice() for
                // instantiating the block mode, but wrap the IV explictly first to have
                // all possible error paths out of the way, thereby enabling a zero copy
                // construction right onto the stack.
                let iv_len = <mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))
                                                                                     as crypto_common::IvSizeUser>
                                                                                 ::IvSize::to_usize();
                if iv.len() != iv_len {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = &iv_out {
                    if iv_out.len() != iv_len {
                        return Err(CryptoError::Internal);
                    }
                }

                let iv = crypto_common::Iv::<
                    mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size)),
                >::from_slice(iv);

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockDecrypt, hence BlockDecryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_iv_init(
                    $block_cipher_impl_instance,
                    iv,
                )
            }};
        }

        // Generate code snippet for the instantiation of (external) mode
        // implementations implementing the crypto_common::InnerInit trait.
        #[allow(unused_macros)]
        macro_rules! gen_inner_init_trait_mode_decryptor_impl_instance_new_snippet {
            ($mode_id:tt, $block_alg_id:tt, $key_size:tt, $block_cipher_impl_instance:ident) => {{
                if iv.len() != 0 {
                    return Err(CryptoError::InvalidIV);
                } else if let Some(iv_out) = iv_out {
                    if iv_out.len() != 0 {
                        return Err(CryptoError::Internal);
                    }
                }

                // Note that the block cipher instance is a reference, which implements
                // crypto_common's BlockDecrypt, hence BlockDecryptMut. This reduces the mode
                // instance's size on the stack significantly.
                <mode_to_dec_impl!($mode_id, block_cipher_to_impl!($block_alg_id, $key_size))>::inner_init(
                    $block_cipher_impl_instance,
                )
            }};
        }

        // Generate code snippet for the block transform callback passed to
        // Self::transform_next_blocks_in_place() for (external) mode implementations
        // implementing the cipher::BlockDecryptMut trait.
        macro_rules! gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet {
            ($mode_transform_impl_instance:ident) => {
                |dst_block: &mut [u8], src_block: Option<&[u8]>| {
                    if let Some(src_block) = src_block {
                        $mode_transform_impl_instance.decrypt_block_b2b_mut(src_block.into(), dst_block.into());
                    } else {
                        $mode_transform_impl_instance.decrypt_block_mut(dst_block.into());
                    }
                }
            };
        }

        // Generate code snippet for obtaining the IV from for (external) mode
        // implementations implementing the cipher::IvState trait.
        #[allow(unused_macros)]
        macro_rules! gen_iv_state_trait_mode_grab_iv_snippet {
            ($mode_transform_impl_instance:ident) => {{
                if let Some(iv_out) = iv_out {
                    iv_out.copy_from_slice($mode_transform_impl_instance.iv_state().deref());
                }
            }};
        }

        // Generate nop code snippet for obtaining the IV from modes with no IV.
        #[allow(unused_macros)]
        macro_rules! gen_grab_iv_nop_snippet {
            ($mode_transform_impl_instance:ident) => {};
        }

        macro_rules! gen_decrypt_with_mode {
            (Ctr $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ctr,
                    true,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Ofb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ofb,
                    true,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Cbc $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cbc,
                    false,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Cfb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Cfb,
                    true,
                    gen_inner_iv_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_iv_state_trait_mode_grab_iv_snippet,
                    dst
                )
            };
            (Ecb $(, $($args:tt),*)?) => {
                gen_match_on_block_cipher_instance!(
                    &self,
                    sym_block_cipher_instance_impl_gen_transform_blocks_in_place_with_mode_and_block_cipher,
                    block_cipher_impl_instance,
                    Ecb,
                    false,
                    gen_inner_init_trait_mode_decryptor_impl_instance_new_snippet,
                    gen_block_decrypt_trait_mode_block_decrypt_transform_cb_snippet,
                    gen_grab_iv_nop_snippet,
                    dst
                )
            };
        }

        gen_match_on_mode!(mode, gen_decrypt_with_mode);

        Ok(())
    }
}

#[cfg(test)]
fn test_mode_supports_partial_last_block(mode: tpm2_interface::TpmiAlgCipherMode) -> bool {
    macro_rules! gen_mode_supports_partial_last_block {
        (Ctr) => {
            true
        };
        (Ofb) => {
            true
        };
        (Cbc) => {
            false
        };
        (Cfb) => {
            true
        };
        (Ecb) => {
            false
        };
    }

    gen_match_on_mode!(mode, gen_mode_supports_partial_last_block)
}

#[cfg(test)]
fn test_encrypt_decrypt(mode: tpm2_interface::TpmiAlgCipherMode, block_cipher_alg: SymBlockCipherAlg) {
    use alloc::vec;

    let key_len = block_cipher_alg.key_len();
    let key = vec![0xffu8; key_len];
    let key = SymBlockCipherKey::try_from((block_cipher_alg, key.as_slice())).unwrap();

    let block_cipher_instance = key.instantiate_block_cipher().unwrap();

    let block_len = block_cipher_alg.block_len();
    let msg_len = if test_mode_supports_partial_last_block(mode) {
        4 * block_len - 1
    } else {
        4 * block_len
    };
    let mut msg = vec![0u8; msg_len];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8
    }

    let iv_len = block_cipher_instance.iv_len_for_mode(mode);
    let mut encrypted = vec![0u8; msg_len];
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for r in [0..3 * block_len, 3 * block_len..msg_len] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (src0, src1) = msg[r.clone()].split_at(r_len / 4);
        let (dst0, dst1) = encrypted[r].split_at_mut(r_len / 4 * 3);
        block_cipher_instance
            .encrypt(
                mode,
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                io_slices::BuffersSliceIoSlicesIter::new(&[src0, src1]).map_infallible_err(),
                Some(&mut iv_out),
            )
            .unwrap();
    }
    assert_ne!(&msg, &encrypted);

    // Decrypt, also in two steps, and compare the result with the original message.
    let mut decrypted = vec![0u8; msg_len];
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for r in [0..3 * block_len, 3 * block_len..msg_len] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (src0, src1) = encrypted[r.clone()].split_at(r_len / 4);
        let (dst0, dst1) = decrypted[r].split_at_mut(r_len / 4 * 3);
        block_cipher_instance
            .decrypt(
                mode,
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                io_slices::BuffersSliceIoSlicesIter::new(&[src0, src1]).map_infallible_err(),
                Some(&mut iv_out),
            )
            .unwrap();
    }
    assert_eq!(&msg, &decrypted);
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ctr_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ofb_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cbc_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_cfb_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_ecb_aes256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia192() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ctr_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ofb_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cbc_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_cfb_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_ecb_camellia256() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ctr", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ctr_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ofb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ofb_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cbc", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_cbc_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cfb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_cfb_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ecb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_ecb_sm4_128() {
    test_encrypt_decrypt(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(test)]
fn test_encrypt_decrypt_in_place(mode: tpm2_interface::TpmiAlgCipherMode, block_cipher_alg: SymBlockCipherAlg) {
    use alloc::vec;

    let key_len = block_cipher_alg.key_len();
    let key = vec![0xffu8; key_len];
    let key = SymBlockCipherKey::try_from((block_cipher_alg, key.as_slice())).unwrap();

    let block_cipher_instance = key.instantiate_block_cipher().unwrap();

    let block_len = block_cipher_alg.block_len();
    let msg_len = if test_mode_supports_partial_last_block(mode) {
        4 * block_len - 1
    } else {
        4 * block_len
    };
    let mut msg = vec![0u8; msg_len];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (i % u8::MAX as usize) as u8
    }

    let iv_len = block_cipher_instance.iv_len_for_mode(mode);
    let mut dst = vec![0u8; msg_len];
    dst.copy_from_slice(&msg);
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for r in [0..3 * block_len, 3 * block_len..msg_len] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (dst0, dst1) = dst[r].split_at_mut(r_len / 4);
        block_cipher_instance
            .encrypt_in_place(
                mode,
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                Some(&mut iv_out),
            )
            .unwrap();
    }
    assert_ne!(&msg, &dst);

    // Decrypt, also in two steps, and compare the result with the original message.
    let mut iv_out = vec![0xccu8; iv_len];
    // Encrypt in two steps for testing the intermediate IV extraction code.
    for r in [0..3 * block_len, 3 * block_len..msg_len] {
        let iv = iv_out.clone();
        let r_len = r.len();
        let (dst0, dst1) = dst[r].split_at_mut(r_len / 4 * 3);
        block_cipher_instance
            .decrypt_in_place(
                mode,
                &iv,
                io_slices::BuffersSliceIoSlicesMutIter::new(&mut [dst0, dst1]).map_infallible_err(),
                Some(&mut iv_out),
            )
            .unwrap();
    }
    assert_eq!(&msg, &dst);
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes192),
    )
}

#[cfg(all(feature = "ctr", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ofb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cbc", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "cfb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ecb", feature = "aes"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_aes256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes256),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia192() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia192),
    )
}

#[cfg(all(feature = "ctr", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ofb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cbc", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "cfb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ecb", feature = "camellia"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_camellia256() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia256),
    )
}

#[cfg(all(feature = "ctr", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ctr_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ctr,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ofb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ofb_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ofb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cbc", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_cbc_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cbc,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "cfb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_cfb_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Cfb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(all(feature = "ecb", feature = "sm4"))]
#[test]
fn test_encrypt_decrypt_in_place_ecb_sm4_128() {
    test_encrypt_decrypt_in_place(
        tpm2_interface::TpmiAlgCipherMode::Ecb,
        SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128),
    )
}

#[cfg(test)]
macro_rules! cfg_select_block_cipher_alg {
    (($f:literal, $id:expr)) => {
        #[cfg(feature = $f)]
        return $id;
        #[cfg(not(feature = $f))]
        {
            "Force compile error for no block cipher configured"
        }
    };
    (($f:literal, $id:expr), $(($f_more:literal, $id_more:expr)),+) => {
        #[cfg(feature = $f)]
        return $id;
        #[cfg(not(feature = $f))]
        {
            cfg_select_hash!($(($f_more, $id_more)),+)
        }
    };
}

#[cfg(test)]
pub const fn test_block_cipher_alg() -> SymBlockCipherAlg {
    cfg_select_block_cipher_alg!(
        ("aes", SymBlockCipherAlg::Aes(SymBlockCipherAesKeySize::Aes128)),
        (
            "camellia",
            SymBlockCipherAlg::Camellia(SymBlockCipherCamelliaKeySize::Camellia128)
        ),
        ("sm4", SymBlockCipherAlg::Sm4(SymBlockCipherSm4KeySize::Sm4_128))
    );
}

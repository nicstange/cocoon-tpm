// SPDX-License-Identifier: Apache-2.0
// Copyright 2023-2025 SUSE LLC
// Author: Nicolai Stange <nstange@suse.de>

//! Implementation of ECDH (C(1e, 1s) scheme).
//!
//! Refer to NIST SP800-56Ar3 and TCG TPM2 Library, Part 1, section C.6.1
//! ("ECDH").

extern crate alloc;
use alloc::vec::Vec;

use super::{curve, key};

use crate::{
    hash,
    kdf::{self, Kdf as _},
    rng, CryptoError,
};
use crate::{
    tpm2_interface,
    utils_common::{
        alloc::{try_alloc_vec, try_alloc_zeroizing_vec},
        io_slices::{self, IoSlicesIterCommon as _},
        zeroize,
    },
};

enum _EcdhCdhError {
    PointIsIdentity,
}

fn _ecdh_c_1e_1s_cdh_compute_z(
    curve_ops: &curve::CurveOps,
    local_priv_key: &key::EccPrivateKey,
    remote_pub_key: &key::EccPublicKey,
) -> Result<Result<zeroize::Zeroizing<Vec<u8>>, _EcdhCdhError>, CryptoError> {
    let mut curve_ops_scratch = curve_ops.try_alloc_scratch()?;
    let d_q = curve_ops.point_scalar_mul(
        &local_priv_key.get_d(),
        remote_pub_key.get_point(),
        &mut curve_ops_scratch,
    )?;
    let h_d_q =
        curve_ops.point_double_repeated(d_q, curve_ops.get_curve().get_cofactor_log2(), &mut curve_ops_scratch)?;

    let mut z_buf = try_alloc_zeroizing_vec::<u8>(curve_ops.get_curve().get_p_len())?;
    let mut z = cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut z_buf);
    h_d_q
        .into_affine_plain_coordinates(&mut z, None, curve_ops.get_field_ops(), Some(&mut curve_ops_scratch))
        .map(|r| {
            r.map(|_| z_buf).map_err(|e| match e {
                curve::ProjectivePointIntoAffineError::PointIsIdentity => _EcdhCdhError::PointIsIdentity,
            })
        })
}

fn _ecdh_c_1e_1s_cdh_derive_shared_secret(
    z: &[u8],
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,
    kdf_label: &str,
    pub_key_u_x: &[u8],
    pub_key_v_x: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // TCG TPM2 Library, Part 1, section C.6.1 ("ECDH"): the shared secret's
    // ("seed" in the referenced section's terminology) length will be
    // the size of the digest produced by the hash algorithm.
    let digest_len = hash::hash_alg_digest_len(kdf_hash_alg);
    let mut shared_secret = try_alloc_zeroizing_vec::<u8>(digest_len as usize)?;

    // TCG TPM2 Library, Part 1, section C.6.1 ("ECDH"): PartyUInfo and
    // PartyVInfo respectively are to be set to the respective x-coordinates
    // of the parties' associated public keys each.
    let kdf_e = kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE::new(
        kdf_hash_alg,
        z,
        kdf_label,
        pub_key_u_x,
        pub_key_v_x,
        8 * (digest_len as u32),
    )
    .unwrap();
    kdf_e.generate(io_slices::SingletonIoSliceMut::new(&mut shared_secret).map_infallible_err())?;
    Ok(shared_secret)
}

fn _ecdh_c_1e_1s_cdh_party_v_z_gen(
    curve_ops: &curve::CurveOps,
    key_v: &key::EccKey,
    pub_key_u_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // In the terminology of NIST SP800-56Ar3, party V (the local party) contributes
    // the static key, party U (the remote party) an ephemeral key.
    // First convert the externally provided TpmsEccPoint into the internal
    // EccPublicKey representation. This stabilizes pub_key_u_plain, next to
    // validating it.
    let pub_key_u = key::EccPublicKey::try_from((curve_ops, pub_key_u_plain))?;

    // The CDH primitive would end up at the point at infinity only if the peer sent
    // some bogus ephemeral public key, abort in this case.
    _ecdh_c_1e_1s_cdh_compute_z(curve_ops, key_v.priv_key().ok_or(CryptoError::NoKey)?, &pub_key_u)?
        .map_err(|_| CryptoError::InvalidResult)
}

/// Generate the `Z` from a local private and a remote public key.
///
/// <div class="warning">
///
/// Do not use directly as an encryption key, `Z` must get run through a
/// suitable KDF.
///
/// </div>
pub fn ecdh_c_1e_1s_cdh_party_v_z_gen(
    key_v: &key::EccKey,
    pub_key_u_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    let curve = curve::Curve::new(key_v.pub_key().get_curve_id())?;
    let curve_ops = curve.curve_ops()?;
    _ecdh_c_1e_1s_cdh_party_v_z_gen(&curve_ops, key_v, pub_key_u_plain)
}

/// Generate a shared encryption key from a local static private key and a
/// remote public key.
///
/// # Arguments:
///
/// * `kdf_hash_alg` - The hash algorithm to use for
///   [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE). The produced shared secret
///   will have the same length as the digest.
/// * `kdf_label` - The label to use for the
///   [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE)'s `usage` parameter.
/// * `key_v` - The local private key.
/// * `pub_key_u_plain` - The remote public key.
pub fn ecdh_c_1e_1s_cdh_party_v_key_gen(
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,
    kdf_label: &str,
    key_v: &key::EccKey,
    pub_key_u_plain: &tpm2_interface::TpmsEccPoint<'_>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    // In the terminology of NIST SP800-56Ar3, party V (the local party) contributes
    // the static key, party U (the remote party) an ephemeral key.
    let curve = curve::Curve::new(key_v.pub_key().get_curve_id())?;
    let curve_ops = curve.curve_ops()?;

    let z = _ecdh_c_1e_1s_cdh_party_v_z_gen(&curve_ops, key_v, pub_key_u_plain)?;

    let pub_key_u_x = &pub_key_u_plain.x.buffer;
    let mut pub_key_v_x = try_alloc_vec::<u8>(curve_ops.get_curve().get_p_len())?;
    key_v.pub_key().get_point().to_plain_coordinates(
        &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut pub_key_v_x),
        None,
        curve_ops.get_field_ops(),
    )?;

    _ecdh_c_1e_1s_cdh_derive_shared_secret(&z, kdf_hash_alg, kdf_label, pub_key_u_x, &pub_key_v_x)
}

/// Generate a shared encryption key from a local ephemeral private key and a
/// remote public key.
///
/// The local ephemeral ECC key will get generated on the fly, with its private
/// key part being destroyed after the operation is complete.
/// The public part gets returned alongside the shared secret.
///
/// # Arguments:
///
/// * `kdf_hash_alg` - The hash algorithm to use for
///   [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE). The produced shared secret
///   will have the same length as the digest.
/// * `kdf_label` - The label to use for the
///   [`KDFe()`](kdf::tcg_tpm2_kdf_e::TcgTpm2KdfE)'s `usage` parameter.
/// * `pub_key_v` - The remote public key.
/// * `rng` - The [random number generator](rng::RngCore) to be used for
///   generating the ephemeral local key.
/// * `additional_rng_generate_input` - Additional input to pass along to the
///   `rng`'s [generate()](rng::RngCore::generate) primitive.
pub fn ecdh_c_1e_1s_cdh_party_u_key_gen(
    kdf_hash_alg: tpm2_interface::TpmiAlgHash,
    kdf_label: &str,
    pub_key_v: &key::EccPublicKey,
    rng: &mut dyn rng::RngCoreDispatchable,
    additional_rng_generate_input: Option<&[Option<&[u8]>]>,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, tpm2_interface::TpmsEccPoint<'static>), CryptoError> {
    // In the terminology of NIST SP800-56Ar3, party V contributes the static key,
    // party U (the local party) an ephemeral key. Generate the ephemeral key
    // first.
    let curve = curve::Curve::new(pub_key_v.get_curve_id())?;
    let curve_ops = curve.curve_ops()?;

    const MAX_RETRIES: u32 = 16;
    let mut remaining_retries = MAX_RETRIES;
    let (pub_key_u, z) = loop {
        if remaining_retries == 0 {
            return Err(CryptoError::RandomSamplingRetriesExceeded);
        }
        remaining_retries -= 1;

        let key_u = key::EccKey::generate(&curve_ops, rng, additional_rng_generate_input)?;
        let priv_key_u = key_u.priv_key().unwrap();
        let z = match _ecdh_c_1e_1s_cdh_compute_z(&curve_ops, priv_key_u, pub_key_v)? {
            Ok(z) => z,
            Err(e) => match e {
                _EcdhCdhError::PointIsIdentity => {
                    continue;
                }
            },
        };

        break (key_u.take_public(), z);
    };

    let pub_key_u_plain = pub_key_u.into_tpms_ecc_point(curve_ops.get_field_ops())?;
    let pub_key_u_x = &pub_key_u_plain.x.buffer;
    let mut pub_key_v_x = try_alloc_vec::<u8>(curve_ops.get_curve().get_p_len())?;
    pub_key_v.get_point().to_plain_coordinates(
        &mut cmpa::MpMutBigEndianUIntByteSlice::from_bytes(&mut pub_key_v_x),
        None,
        curve_ops.get_field_ops(),
    )?;

    Ok((
        _ecdh_c_1e_1s_cdh_derive_shared_secret(&z, kdf_hash_alg, kdf_label, pub_key_u_x, &pub_key_v_x)?,
        pub_key_u_plain,
    ))
}

#[test]
fn test_ecdh_c_1e_1s_cdh_key_gen() {
    // Test a pairwise key establishment and verify both parties end up at the same
    // shared secret.
    let curve_id = curve::test_curve_id();
    let curve = curve::Curve::new(curve_id).unwrap();
    let curve_ops = curve.curve_ops().unwrap();
    let kdf_hash_alg = hash::test_hash_alg();
    const KDF_LABEL: &str = "test ECDH key establishment";
    let mut drbg = rng::test_rng();

    // First generate a static test key for party V.
    let key_v = key::EccKey::generate(&curve_ops, &mut drbg, None).unwrap();

    // Let party U initiated the ECDH establishment.
    let (shared_secret_u, mut pub_key_u_plain) =
        ecdh_c_1e_1s_cdh_party_u_key_gen(kdf_hash_alg, KDF_LABEL, key_v.pub_key(), &mut drbg, None).unwrap();

    // And let party V establish the shared secret with the ephemeral public key
    // conveyed by party U.
    let shared_secret_v =
        ecdh_c_1e_1s_cdh_party_v_key_gen(kdf_hash_alg, KDF_LABEL, &key_v, &mut pub_key_u_plain).unwrap();

    assert_eq!(&shared_secret_u, &shared_secret_v);
}

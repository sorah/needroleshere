/*
 * This source code contains a modified part of ecdsa crate. This module is a implementation of
 * RandomizedDigestSigner which uses SHA256 always regardless of key size (e.g. P-384).
 *
 * https://github.com/RustCrypto/signatures/blob/master/ecdsa/src/hazmat.rs
 *
 * Copyright 2018-2022 RustCrypto Developers
 * SPDX-License-Identifier: Apache-2.0
 */

// Sadly using RustCrypto huzmat to sign with sha256 digest using P-384 key. Following
// RandomizedDigestSigner. This implementation is not used with P256.
//
// try_sign_prehash may be useful but we want to bring rng for k generation as Go crypto/ecdsa does
// which the original Go helper implementation uses.
//
// https://github.com/RustCrypto/traits/pull/1099

pub(crate) fn sign<C>(
    signing_key: ecdsa::SigningKey<C>,
    string_to_sign: &[u8],
) -> Result<ecdsa::Signature<C>, crate::error::Error>
where
    C: ecdsa::elliptic_curve::PrimeCurveArithmetic + ecdsa::hazmat::DigestPrimitive,
    C::Uint: for<'a> From<&'a ecdsa::elliptic_curve::Scalar<C>>, // From<&'a Self>; satisfied by `ScalarArithmetic::Scalar: Into<Self::UInt>`
    C::Digest: ecdsa::signature::digest::Digest
        + ecdsa::signature::digest::core_api::BlockSizeUser
        + ecdsa::signature::digest::FixedOutput<
            OutputSize = <C as elliptic_curve::Curve>::FieldBytesSize,
        > + ecdsa::signature::digest::FixedOutputReset,
    ecdsa::elliptic_curve::Scalar<C>: ecdsa::elliptic_curve::ops::Invert<
            Output = ecdsa::elliptic_curve::subtle::CtOption<ecdsa::elliptic_curve::Scalar<C>>,
        > + ecdsa::elliptic_curve::ops::Reduce<C::Uint>
        + ecdsa::hazmat::SignPrimitive<C>,
    ecdsa::SignatureSize<C>: ecdsa::elliptic_curve::generic_array::ArrayLength<u8>,
{
    use sha2::Digest as _;
    let digest = sha2::Sha256::new_with_prefix(string_to_sign);
    sign_inner(signing_key, digest)
}

//   Self: From<ScalarCore<C>>,

fn sign_inner<C, D>(
    signing_key: ecdsa::SigningKey<C>,
    digest: D,
) -> Result<ecdsa::Signature<C>, crate::error::Error>
where
    C: ecdsa::elliptic_curve::PrimeCurveArithmetic + ecdsa::hazmat::DigestPrimitive,
    C::Uint: for<'a> From<&'a ecdsa::elliptic_curve::Scalar<C>>, // From<&'a Self>; satisfied by `ScalarArithmetic::Scalar: Into<Self::UInt>`
    C::Digest: ecdsa::signature::digest::Digest
        + ecdsa::signature::digest::core_api::BlockSizeUser
        + ecdsa::signature::digest::FixedOutput<
            OutputSize = <C as elliptic_curve::Curve>::FieldBytesSize,
        > + ecdsa::signature::digest::FixedOutputReset,
    D: ecdsa::signature::digest::Digest
        + ecdsa::signature::digest::core_api::BlockSizeUser
        + ecdsa::signature::digest::FixedOutput<
            OutputSize = ecdsa::elliptic_curve::generic_array::typenum::U32, // XXX: better specify?
        > + ecdsa::signature::digest::FixedOutputReset,
    ecdsa::elliptic_curve::Scalar<C>: ecdsa::elliptic_curve::ops::Invert<
            Output = ecdsa::elliptic_curve::subtle::CtOption<ecdsa::elliptic_curve::Scalar<C>>,
        > + ecdsa::elliptic_curve::ops::Reduce<C::Uint>
        + ecdsa::hazmat::SignPrimitive<C>,
    ecdsa::SignatureSize<C>: ecdsa::elliptic_curve::generic_array::ArrayLength<u8>,
{
    use ecdsa::hazmat::SignPrimitive as _;
    use rand::RngCore as _;
    //use sha2::digest::FixedOutput as _;
    //use sha2::Digest as _;

    // try_sign_digest_with_rng
    let mut ad = ecdsa::elliptic_curve::FieldBytes::<C>::default();
    rand::thread_rng().fill_bytes(&mut ad);
    let secret_scalar = signing_key.as_nonzero_scalar();

    // try_sign_digest_rfc6979
    let src: [u8; 32] = digest.finalize_fixed().into(); // GenericArray
    let scalar = ecdsa::hazmat::bits2field::<C>(&src)?;

    Ok(secret_scalar
        .try_sign_prehashed_rfc6979::<C::Digest>(&scalar, &ad)?
        .0)

    // XXX: Add to FieldSize<C> fails in this function (why?) thus to_der() can't be done here
    //{
    //    use core::ops::Add;
    //    use ecdsa::elliptic_curve::bigint;
    //    use ecdsa::elliptic_curve::bigint::prelude::ArrayEncoding;
    //    use ecdsa::elliptic_curve::generic_array::typenum;
    //    use ecdsa::elliptic_curve::generic_array::typenum::Unsigned;
    //    use ecdsa::elliptic_curve::Curve;
    //    use ecdsa::elliptic_curve::FieldSize;
    //    use ecdsa::SignatureSize;
    //    let i = FieldSize::<C>::to_u64(); // 48
    //    let i = <FieldSize<C> as Add>::Output::to_u64(); // 96
    //    let i = <<bigint::U384 as ArrayEncoding>::ByteSize as Add<typenum::U1>>::Output::U64;
    //    let i = <<<p384::NistP384 as Curve>::UInt as ArrayEncoding>::ByteSize as Add<
    //        typenum::U1,
    //    >>::Output::U64;
    //    //let i = <<<C as Curve>::UInt as ArrayEncoding>::ByteSize as Add<typenum::U1>>::Output::U64;
    //    let i = <FieldSize<p384::NistP384> as Add<typenum::N1>>::Output::U64;
    //    let i = <FieldSize<C> as Add<typenum::N1>>::Output::U64;

    //    //let i = <FieldSize<C> as Add<typenum::U3>>::Output::to_u64();
    //    //let i = <<C as Curve>::UInt as Add<typenum::U3>>::Output::to_u64();
    //    panic!("{}", i)
    //}
    //Ok(signature)
}

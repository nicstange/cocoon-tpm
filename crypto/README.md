# Cocoon TPM project - `cocoon-tpm-crypto` crate

This `[no_std]` crates provides all cryptographic primitives needed by
any other components of the project.

Note that grouping all cryptography implementation related code
together in a single crate with a well-defined interface makes it
fairly straight-forward to create alternative drop-in replacements
binding against other crypto libraries.

For any symmetric cryptography, most notably hashes and block ciphers,
the respective `cocoon-tpm-crypto` primitives simply route to the
respective implementations provided by the [RustCrypto
project](https://github.com/rustcrypto).

For asymmetric cryptography however, the [RustCrypto
project](https://github.com/rustcrypto) crates do not really lend
themselves to stack constrained execution environments. For this and
some other reasons, the `cocoon-tpm-crypto` crate brings its own RSA
and ECC implementations, built on the [`Cryptographic MultiPrecision
Arithmetic crate`](https://github.com/nicstange/cmpa-rs) enabling
complete control over the buffer allocations.

See the output of `cargo doc` for a reference.

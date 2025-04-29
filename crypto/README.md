# Cocoon TPM project - `cocoon-tpm-crypto` crate

This `[no_std]` crates provides all cryptographic primitives needed by
any other components of the project.

See the output of `cargo doc` for an API reference.

Two possible backend implementations are supported: a pure Rust one
and one linking against
[BoringSSL](https://github.com/google/boringssl). By default, the
pure Rust backend is selected. For the BoringSSL one, enable the
`boringssl` Cargo feature.

## Pure Rust backend
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

## BoringSSL backend
When the BoringSSL backend is selected, i.e. if the `boringssl` Cargo
feature is enabled, all cryptography requests will get forwarded to
BoringSSL through a FFI.

The set of supported algorithms is necessarily restricted to what's
provided by BoringSSL. Furthermore, it's currently not possible to
use RSA with the BoringSSL backend.

The bare FFI itself, including a compilation of BoringSSL, is handled
by a separate crate, `bssl-bare-sys`.  Refer to its documentation for
hints about integration into freestanding/embedded-like environments.

**Note that the copy of BoringSSL is distributed as a git submodule
under the `bssl-bare-sys` crate, it must get initialized first!**

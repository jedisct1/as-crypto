# as-crypto

Sample [AssemblyScript](https://assemblyscript.org) bindings for a [WASI cryptography API proposal](https://github.com/jedisct1/wasi-crypto-preview).

These are not meant to be used by anything.

The purpose of these bindings is to evaluate the usability of the API in the context of a programming language that radically differs from Rust (memory management, type system, tooling).

It also provides a test bed for the AssemblyScript [witx code generator](https://github.com/jedisct1/as-witx/).

Executing the resulting WebAssembly file requires [a version of `wasmtime` that includes the crypto modules](https://github.com/jedisct1/wasmtime-crypto).

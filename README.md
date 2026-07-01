# eth-crypto-clj

[![CI](https://github.com/kotoba-lang/eth-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/kotoba-lang/eth-crypto/actions/workflows/ci.yml)

Standalone, **dependency-free** Ethereum crypto primitives for Clojure — runs
unchanged under **babashka** and the JVM (only `clojure.*` + `java.math.BigInteger`).

Sibling of [`kotoba-lang/ed25519`](https://github.com/kotoba-lang/ed25519):
where that covers the did:key / Ed25519 side, this covers the **Ethereum
secp256k1 / Keccak-256 / EIP-712** side in Clojure.

## Why pure Clojure (not BouncyCastle)

babashka is a GraalVM *native image*: it can only use Java classes baked into the bb
binary. Arbitrary jars on the classpath are **not** loadable at runtime
(`java.security` exposes SHA3-256 but **not** Keccak-256, and any `org.bouncycastle.*`
import throws `ClassNotFoundException`). So Keccak-256 is the Keccak-f[1600] permutation
implemented here, and secp256k1 ecrecover uses `java.math.BigInteger` (which IS available
in bb). The result runs identically on bb and the JVM with zero native dependencies.

## API (`eth-crypto.core`)

| fn | in → out |
|---|---|
| `keccak256` | bytes → 32 bytes (Keccak-256, **not** SHA3-256) |
| `eip55-checksum` | 20-byte addr / hex → EIP-55 mixed-case `0x…` string |
| `encode-type` / `type-hash` | EIP-712 type encoding + `keccak256` thereof |
| `encode-data` / `hash-struct` | EIP-712 struct encoding + hash |
| `domain-separator` | EIP-712 domain separator |
| `eip712-digest` | `(domain types primary message) →` the `keccak256(0x1901‖domainSep‖structHash)` digest |
| `ecrecover` | `(digest sig)` → 20-byte signer address (secp256k1 public-key recovery) |
| `ecrecover-checksum` | as above → EIP-55 checksummed `0x…` |
| `private->public` | 32-byte privkey → 64-byte uncompressed pubkey (`X‖Y`, no `0x04`) |
| `address-of-privkey` | 32-byte privkey → EIP-55 `0x…` address |
| `secp256k1-sign` | `(privkey digest)` → `{:r :s :recovery-id}` — deterministic ECDSA (**RFC 6979** HMAC-SHA256 nonce) with EIP-2 low-s |
| `rlp-encode` | byte-string / nested list → canonical Ethereum **RLP** bytes |
| `sign-tx-legacy` | `(tx privkey)` → `0x…` raw signed **EIP-155** legacy tx (replaces python `eth_account`) |
| `hex->bytes` / `bytes->hex` / `strip0x` / `utf8` | byte/hex helpers |

## Verification

Verified against the canonical **EIP-712 "Ether Mail" spec vector**
(eips.ethereum.org/EIPS/eip-712):

```clojure
;; digest of the spec Mail message
(= (bytes->hex (eip712-digest domain types "Mail" message))
   "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2")  ;=> true
;; recover the spec signature → the spec signer
(= (ecrecover-checksum digest spec-signature)
   "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")                        ;=> true
```

plus Keccak-256 and EIP-55 known-answer vectors.

The **signing** side is gated against the canonical **EIP-155 worked example**
(privkey `0x4646…46`, the EIP-155 spec tx) — the signing hash, `v=37`/`r`/`s`, and
the full raw signed tx all match byte-for-byte, plus a sign→`ecrecover` roundtrip and
an `address-of-privkey` vector — see `test/eth_crypto/test_signing.cljc`:

```bash
clojure -M:test
# Ran 5 tests containing 7 assertions. 0 failures, 0 errors.
```

## Usage

```clojure
;; deps.edn / bb.edn
io.github.kotoba-lang/eth-crypto {:git/sha "<sha>"}

;; code
(require '[eth-crypto.core :as eth])
(eth/eip712-digest domain types "CreditorConsent" message)
(eth/ecrecover-checksum digest signature)   ;=> "0x…"
```

## Test

```bash
clojure -M:test
# Ran 5 tests containing 7 assertions. 0 failures, 0 errors.
```

## License

Apache-2.0. First-party org library; the etzhayyim Charter Compliance Rider applies to
first-party consumers per their own NOTICE.

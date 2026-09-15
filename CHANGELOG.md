# Changelog

Every published version, newest first. This file is on the publish
allow-list, so it travels with the package: it is the only thing a
consumer deciding whether to upgrade can read.

## 0.0.2 — 2026-09-15

README rewritten to the package README style guide (docs/writing-a-readme.md); no change to the interface.

## 0.0.1 — 2026-09-11

The **interface**, before anyone implements it.  Every signature, every
type and every effect row is published; every body is `todo()`, and the
release is stamped `NOT IMPLEMENTED — interface only`.  Adding this
package works and calling it panics.

- Six modules.  `asn1tag` is the identifier and length octets as
  integer arithmetic; `asn1read` is the reader, by offset and by
  feeding; `asn1univ` is the universal types; `asn1oid` is object
  identifiers and their arcs; `asn1write` is a writer into the caller's
  buffer with a builder beside it; `asn1pkix` is the four structures
  the crypto tier parses keys and certificates out of.
- **`AsnSpan` is the load-bearing interface.**  Every reader answers a
  span into the caller's own bytes rather than a copy, because a
  certificate's signature is computed over the DER bytes of its
  TBSCertificate exactly as they arrived.  A parser that made the
  caller rebuild those bytes would fail on documents that are perfectly
  valid.
- **DER by default, BER by a flag, and the writer has no flag at
  all.**  The five rules BER allows and DER does not each have a
  refusal of their own name, `asn1err.is_der_only` says which those
  are, and the README says why accepting a second encoding is how a
  signature checks out over something the reader did not read.  One BER
  rule is never lifted: a time without a `Z`.
- **The device claim is built.**  `tests/embedded_probe.nv` compiles
  `asn1tag` to a Cortex-M4 ELF for `--target=nrf52-qemu`.  The consumer
  is a device provisioned with a public key that has to walk a
  certificate's headers and compare one OBJECT IDENTIFIER, and every
  step of that is arithmetic in registers.
- **Four things a wrong parser gets wrong quietly** are each a test:
  the first two OID arcs share one byte and the division by 40 is
  capped at 2 (X.690's own `2.100.3` vector); an Ed25519 key's
  algorithm parameters are ABSENT and not NULL; an Ed25519 PKCS#8 seed
  is wrapped in two OCTET STRINGs; an ECDSA signature is a DER
  SEQUENCE of two shortest-form INTEGERs and not sixty-four fixed
  bytes.
- **No signature verification, and the boundary is stated.**
  `ec_public_key_point` hands over exactly what
  `p256.public_key_from_bytes` takes and `ed25519_public_key` exactly
  what `ed25519.verifying_key_from_bytes` takes; digests, signatures
  and chains belong to those packages.
- **No PEM, no SEC 1 `EC PRIVATE KEY`, no RSA.**  Each is named in the
  README with its reason, and `asn1oid.oid_rsa_encryption` exists so a
  parser can say "this is an RSA key and nothing here reads one".
- Depends on calendar-nv, which is what turns UTCTime's two-digit year
  into a civil date — the rule nobody should have to rediscover.
- Every vector is X.690's, RFC 5280's, or RFC 8410 § 10's, decoded from
  the base64 the RFC prints.

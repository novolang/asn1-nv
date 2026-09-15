# asn1-nv

ASN.1 is a notation for describing data structures, and DER, the
Distinguished Encoding Rules, is one way of writing values of those
structures as bytes. Every X.509 certificate, every PKCS#8 private key
and a good deal of telecommunications signalling is DER. The encoding is
specified in
[ITU-T X.690](https://www.itu.int/rec/T-REC-X.690). This package reads
and writes it, and reads the certificate and key structures of
[RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) on top.

**Status: NOT IMPLEMENTED — interface only.** Every function is declared
with its full signature, but every body is a `todo()` that panics when
called. The package is published so its design can be reviewed and
depended on before it is implemented. Version 0.1.0 will be the first
working release.

## What DER is

A DER document is one value, and a value is three parts. The
**identifier** says what the value is: its class, whether it is
primitive or constructed, and its tag number. The **length** says how
many bytes of content follow. The **content** is those bytes, and for a
constructed value they are more values of the same shape. That is the
whole format.

A length below 128 is one byte and is that number. Any other length is a
byte whose top bit is set and whose low seven bits say how many length
bytes follow, most significant first.

The **universal class** holds the types the standard itself defines:
BOOLEAN, INTEGER, BIT STRING, OCTET STRING, NULL, OBJECT IDENTIFIER,
UTF8String, PrintableString, IA5String, UTCTime, GeneralizedTime,
SEQUENCE and SET. The other classes are for tags a structure's own
definition gives meaning to.

An **OBJECT IDENTIFIER** is a sequence of numbers called arcs, written
as `1.2.840.10045.2.1`. It names things: a hash, a signature algorithm,
a curve, an attribute of a name. The first two arcs share one byte, as
`40 * first + second`, and the rest are base 128 with the top bit set
while more bytes follow.

DER is BER, the Basic Encoding Rules, with the choices taken away. Every
rule it adds exists so that **one value has exactly one encoding**,
because a signature is computed over bytes.

| Rule | BER | DER |
| --- | --- | --- |
| A length in the long form the short form could hold | allowed | forbidden, `AsnNonMinimalLength` |
| An indefinite length, `0x80` | allowed | forbidden, `AsnIndefiniteLength` |
| A BOOLEAN that is not `0x00` or `0xff` | allowed | forbidden, `AsnBadBoolean` |
| An INTEGER with a redundant leading byte | allowed | forbidden, `AsnNonMinimalInteger` |
| A SET OF whose elements are not in ascending order | allowed | forbidden, `AsnSetOfNotSorted` |

| Quantity | Value |
| --- | --- |
| Longest length in the short form | 127 |
| Length byte reserved and unusable | `0xFF` |
| Default nesting limit | 64 |
| Default limit on one value's content | 16 MiB |
| Highest unused-bit count in a BIT STRING | 7 |
| Only encoding of NULL | `05 00` |
| Cap on the first OID arc | 2 |
| UTCTime years 50 to 99 mean | 1950 to 1999 |
| UTCTime years 00 to 49 mean | 2000 to 2049 |

## Install

```
novo pkg add asn1-nv
```

## Example

```novo
use std.bytes
use asn1read
use asn1univ

fn main() [io]
    // 30 03 02 01 07: a SEQUENCE whose content is the INTEGER 7.
    let der = bytes.from_hex("3003020107") ?? bytes.zeros(0)

    // The values directly inside the SEQUENCE at offset 0, as spans
    // into the caller's own bytes.
    match asn1read.children_at(der, 0, asn1read.default_limits())
        Err(e)   => println(e.message())
        Ok(kids) =>
            // The first child read as an INTEGER.
            match asn1univ.integer_at(der, kids[0].off, asn1read.default_limits())
                Ok(n)  => println("${n}")
                Err(e) => println(e.message())
```

Build and test with `novo pkg build` and `novo test`. Today `novo test`
fails on purpose: every test reaches a `not implemented: <module>.<fn>`
panic. The tests are the specification the implementation will have to
satisfy.

## What the package contains

| Module | Contents |
| --- | --- |
| `asn1tag` | The identifier and length octets as arithmetic over integers, a byte at a time, with the universal tag numbers and the OID arc packing. |
| `asn1read` | Reading by offset and by feeding: the header at an offset, a value's span, the children of a constructed value, the expectations a parser states, and the limits every read is bounded by. |
| `asn1univ` | The universal types: booleans, integers, octet and bit strings, null, object identifiers, the three string types, the two time types, and the three collections. |
| `asn1oid` | Object identifiers as values: arcs in and out, text in and out, comparison and prefix tests, and seventeen identifiers named. |
| `asn1write` | Writing DER into a buffer the caller owns: the size of each form, the fifteen writers, and a builder that closes a constructed value when you end it. |
| `asn1pkix` | The structures: SubjectPublicKeyInfo, PKCS#8, an X.509 certificate, distinguished names, four extensions by name, and the key and signature forms the cryptography packages take. |

## How to choose an entry point

**`asn1read` by offset is how a certificate is read.** The document is
in memory whole, and the calls answer spans into it.

**`asn1read.reader` and `feed` are how a large document arrives.** A
chain over a socket, or a revocation list of a hundred megabytes. The
payload of a primitive value is handed over whole, because the values in
this field are small.

**`asn1pkix` is the entry point for a key or a certificate.** It applies
the structure rules so a caller does not walk the tree by hand.

**`asn1write.builder` is how a document is produced.** Begin a
constructed value, put its members, end it, and the lengths are
back-filled for you.

**`asn1tag` is the format for firmware.** It takes and answers integers,
a byte at a time. See "Running on a microcontroller".

## The rules a user needs

1. **Every reader answers a span, not a copy.** `AsnSpan` is an offset
   and a length into the caller's own bytes. A certificate's signature
   is computed over the bytes of its TBSCertificate exactly as they
   arrived, so a parser that handed back re-encoded values would break
   every certificate whose writer was not byte-for-byte DER.
   `asn1read.span_bytes` is the one call that copies, and it is named so
   that a reader can see where.
2. **The depth bound is not optional.** ASN.1 nesting is unbounded by
   specification, and thirty bytes can ask for a thousand levels.
   `asn1read.default_limits` sets 64 levels and a 16 MiB value, and
   `AsnDepthExceeded` names the limit it passed.
3. **DER is the default and BER tolerance is a flag.**
   `asn1read.ber_limits` accepts the five rules in the table above, and
   `asn1err.is_der_only` says whether a refusal was one of them. Use it
   for a file another tool wrote when no signature is involved. Two
   accepted encodings of one value is how a signature checks out over
   something the reader did not read.
4. **The writer has no tolerance flag.** Everything it produces is DER:
   the shortest length, the shortest integer, `0xff` for true, definite
   lengths throughout, and SET OF elements sorted by their encodings.
5. **A time without a `Z` is refused whatever the flag says.** A local
   offset is legal BER and means a certificate expires at a different
   moment depending on where it is read.
6. **The first two OID arcs share a byte and the division is capped at
   2.** Arc 2 puts no limit on its second component, so `2.100` packs to
   180 and 180 divided by 40 is 4, which is not an arc. The first arc is
   the smaller of that division and 2. X.690 section 8.19 prints
   `2.100.3` as the example, and a parser without the cap misreads every
   attribute type in a certificate's subject.
7. **An INTEGER longer than an `Int` is not a fault in the document.**
   An RSA modulus is 257 bytes and perfectly legal.
   `asn1univ.integer_bytes_at` answers the bytes;
   `asn1univ.integer_at` answers `AsnIntegerTooLarge` when the caller
   asked for a number.
8. **A serial number is compared as bytes, and so is a name.**
   `asn1pkix.names_encode_equal` compares encodings, because that is
   what chain building compares.
9. **An Ed25519 key's algorithm parameters are absent, not NULL.** RFC
   8410 says so. A writer that emitted `05 00` there produces a key much
   of the world refuses.
10. **An Ed25519 PKCS#8 seed is wrapped twice.** The private key OCTET
    STRING's content is itself an OCTET STRING holding the 32 bytes. A
    parser that skipped the inner one hands over 34 bytes that look
    nearly right.
11. **An ECDSA signature is a SEQUENCE of two INTEGERs, not 64 bytes.**
    Each half is shortest-form, so an `r` whose top byte is zero is 31
    bytes. `asn1pkix.ecdsa_signature_rs` converts, and its `width`
    argument is required.
12. **A UTCTime's two-digit year splits at 50.** `asn1univ.utc_year`
    answers 2049 for 49 and 1950 for 50.
13. **An unknown critical extension is a reason to refuse a
    certificate.** RFC 5280 says so, and
    `asn1pkix.unknown_critical_extensions` is the one call that asks.
14. **This package has no clock.** `asn1pkix.is_valid_at` takes the
    moment as an argument.

## Running on a microcontroller

novo-lang lets a package state which of its modules can run on a device
with no heap allocator, and the compiler checks that claim on every
build. Here the claim covers `asn1tag` and nothing else. It takes and
answers integers and scans a byte at a time, which is what a device
reading from a UART or an SPI flash has.

`tests/embedded_probe.nv` is that claim as a program that either builds
or does not. It builds today:

```bash
novo build --target=nrf52-qemu tests/embedded_probe.nv
```

The probe produces a Cortex-M4 executable that scans identifiers and
both length forms, emits them again, and packs and unpacks OID arcs. It
builds and it is not run: every function it calls is a `todo()` today.

The consumer for this is a device provisioned with a public key and
handed a certificate. To decide whether to trust what it was sent, it
walks into the TBSCertificate, into the SubjectPublicKeyInfo, into the
AlgorithmIdentifier, compares one object identifier and takes the key
bytes. All of that is header arithmetic and arc comparison.

**A device cannot use the other five modules.** They speak `Bytes`,
`Str` and `Cursor`, and the embedded runtime defines none of them. One
host-only function anywhere in a compilation unit is an undefined symbol
at link time on a device, whether or not the firmware calls it.

## What is not included

- **Signature verification, digests and chain building.**
  `asn1pkix.ec_public_key_point` hands over exactly what
  [p256-nv](https://novo-lang.org/packages/p256-nv) takes, and
  `asn1pkix.ed25519_public_key` exactly what
  [ed25519-nv](https://novo-lang.org/packages/ed25519-nv) takes. What
  happens next belongs to those packages.
- **Revocation, name constraints and policy mapping.** Certificate
  revocation lists and OCSP responses are not read.
- **PEM.** A `-----BEGIN CERTIFICATE-----` block is base64 with a
  header, and [base64-nv](https://novo-lang.org/packages/base64-nv)
  already has the base64. This package takes DER bytes.
- **SEC 1's standalone `EC PRIVATE KEY` document.**
  `asn1pkix.ec_private_key_scalar` reads the same structure where it
  appears inside a PKCS#8 wrapper.
- **RSA keys.** Nothing on the registry implements RSA.
  `asn1oid.oid_rsa_encryption` is named so that a parser can say "this
  is an RSA key and nothing here reads one" rather than failing
  obscurely.
- **Extensions beyond four by name.** `basicConstraints`, `keyUsage`,
  `subjectAltName` and `extKeyUsage` are decoded. Every other extension
  is carried as its identifier, its critical flag and its raw value.
- **Any input or output.** A certificate arrives as bytes the host read,
  and a document written comes back as bytes the host stores.

## Related packages

- [calendar-nv](https://novo-lang.org/packages/calendar-nv) is this
  package's only dependency. It turns a UTCTime or a GeneralizedTime
  into a civil date, so the two-digit-year rule is applied once here
  rather than by every caller.
- [p256-nv](https://novo-lang.org/packages/p256-nv),
  [ed25519-nv](https://novo-lang.org/packages/ed25519-nv) and
  [crypto-nv](https://novo-lang.org/packages/crypto-nv) are the
  arithmetic this package's outputs feed.
- [tls-nv](https://novo-lang.org/packages/tls-nv) and
  [acme-nv](https://novo-lang.org/packages/acme-nv) are the consumers
  that need certificates parsed.
- [base64-nv](https://novo-lang.org/packages/base64-nv) is the other
  half of reading a PEM file.
- [protobuf-nv](https://novo-lang.org/packages/protobuf-nv) is the other
  tag-length-value format on the registry. Its tags are field numbers
  and its lengths are varints, and it has no canonical form.

## Tests

```bash
novo test tests/asn1_tests.nv        # 93 tests
```

Every vector is from a specification: the two length forms and the
`2.100.3` identifier from X.690 section 8, the certificate structure
from RFC 5280, PKCS#8 from RFC 5208 and RFC 5958, and the Ed25519 public
and private keys printed in RFC 8410 section 10. The implementations to
check a port against are `rasn` in Rust and `asn1crypto` in Python.

The suite asserts that a header is read and written back byte for byte,
that each of the five DER rules is refused by its own name and accepted
under the tolerant limits, that a time without a `Z` is refused under
both, that the OID arc cap holds for `2.100.3`, that nesting past the
limit is refused, that an integer too large for an `Int` is answered as
bytes, that a span is into the caller's bytes, that an Ed25519 key's
parameters are absent, that its seed is wrapped twice, and that an ECDSA
signature converts to two fixed-width halves.

The tests compile today and fail at run, each on the `not implemented`
panic that is its body. That is the expected state of an interface
release. They turn green one at a time as bodies land.

## Implementation status

| Item | Implemented |
| --- | --- |
| `asn1err.decode_offset`, `.is_der_only`, the two `message` impls | no |
| `asn1tag.class_*`, `.constructed_bit`, `.identifier_byte` | no |
| `asn1tag.class_of`, `.is_constructed`, `.tag_of_low`, `.is_high_tag`, `.identifier_len` | no |
| `asn1tag.tag_*`, the fourteen universal numbers | no |
| `asn1tag.length_len`, `.header_len`, `.indefinite_byte`, `.end_of_contents_len` | no |
| `asn1tag.head_scan`, `.head_push`, `.head_need` | no |
| `asn1tag.emit_identifier`, `.emit_length`, `.emit_arc` | no |
| `asn1tag.arc_scan`, `.arc_push`, `.first_arc`, `.second_arc`, `.pack_arcs`, `.arc_len` | no |
| `asn1read.default_limits`, `.ber_limits` | no |
| `asn1read.header_at`, `.value_span_at`, `.content_span_at`, `.next_offset`, `.children_at` | no |
| `asn1read.expect_at`, `.expect_context_at`, `.explicit_at`, `.implicit_at`, `.peek_tag_at` | no |
| `asn1read.read_document`, `.span_bytes`, `.walk`, `.drain` | no |
| `asn1read.reader`, `.feed`, `.finish`, `.offset`, `.pending_len`, `.depth`, `.at_boundary` | no |
| `asn1univ.boolean_at`, `.integer_at`, `.integer_bytes_at`, `.octet_string_at`, `.null_at` | no |
| `asn1univ.bit_string_at`, `.bit_count`, `.bit_at`, `.oid_at` | no |
| `asn1univ.utf8_string_at`, `.printable_string_at`, `.ia5_string_at`, `.any_string_at` | no |
| `asn1univ.utc_time_at`, `.generalized_time_at`, `.any_time_at`, `.utc_year` | no |
| `asn1univ.sequence_at`, `.set_at`, `.set_of_at` | no |
| `asn1univ.is_printable_string`, `.is_ia5_string` | no |
| `asn1oid.oid`, `.arcs_of`, `.arc_count`, `.arc_at`, `.oid_text`, `.oid_of_text` | no |
| `asn1oid.starts_with`, `.equals`, `.encoded_len`, `.encode_into`, `.decode`, `.oid_name` | no |
| `asn1oid.oid_*`, the seventeen named identifiers | no |
| `asn1write.tlv_len`, `.context_tlv_len`, `.integer_len`, `.integer_bytes_len` | no |
| `asn1write.oid_len`, `.bit_string_len`, `.sort_set_of` | no |
| `asn1write.write_*_into`, fifteen writers | no |
| `asn1write.builder`, `.builder_depth`, `.builder_len`, `.build_limits` | no |
| `asn1write.begin_sequence`, `.begin_set`, `.begin_set_of`, `.begin_explicit`, `.end`, `.done` | no |
| `asn1write.put_*`, eleven functions | no |
| `asn1pkix.algorithm_at`, `.spki_at`, `.name_at` | no |
| `asn1pkix.parse_spki`, `.parse_pkcs8`, `.parse_certificate` | no |
| `asn1pkix.extensions_of`, `.extension_by_oid`, `.unknown_critical_extensions` | no |
| `asn1pkix.basic_constraints`, `.key_usage`, `.subject_alt_dns_names`, `.ext_key_usage_oids` | no |
| `asn1pkix.ec_public_key_point`, `.ec_public_key_xy`, `.ec_curve_oid`, `.ec_private_key_scalar` | no |
| `asn1pkix.ed25519_public_key`, `.ed25519_seed` | no |
| `asn1pkix.signature_bytes`, `.ecdsa_signature_rs`, `.ecdsa_signature_der` | no |
| `asn1pkix.algorithms_agree`, `.is_valid_at`, `.name_text`, `.attribute_value`, `.names_encode_equal` | no |
| `asn1pkix.write_spki`, `.write_pkcs8`, `.ec_spki`, `.ed25519_spki` | no |

## Licence

Apache-2.0. See `LICENSE`.

<!-- docs/writing-a-readme.md is the style guide for this page. -->

# asn1-nv

**Status: NOT IMPLEMENTED — interface only.**

Every public function below is published with its signature and its
effect row, and every body is `todo()`.  Installing this package works;
calling it panics with `not implemented`.

## What this is

ASN.1's Distinguished Encoding Rules — the encoding every X.509
certificate, every `.pem` key file, every PKCS#8 private key and a good
deal of telecoms is written in.

The format itself is three parts repeated: an IDENTIFIER saying what a
value is, a LENGTH saying how long its content is, and the CONTENT,
which for a constructed value is more of the same.  That is the whole
of it, and everything hard about ASN.1 is either the rules DER adds on
top or the structures people wrote in it.

Six surfaces, and a reader should know which one they are on.

| surface | module | reach for it when |
| --- | --- | --- |
| the **header** | `asn1tag` | you are on a device, or reading a hexdump |
| the **reader** | `asn1read` | you have a document and want its values |
| the **types** | `asn1univ` | you want an INTEGER, a string, a time |
| the **identifiers** | `asn1oid` | you are comparing algorithms |
| the **writer** | `asn1write` | you are producing a document |
| the **structures** | `asn1pkix` | you have a key or a certificate |

## Adding it, and checking it

```bash
novo pkg add asn1-nv           # into your novo.toml
novo pkg build                 # type- and effect-check the package
novo test --isolate tests/asn1_tests.nv
```

`novo test` is red today and that is the point of the release: all
ninety-three assertions fail with `not implemented: <module>.<fn>`.
They turn green one at a time as bodies land.

## The one example that will work

```novo
use std.bytes
use asn1read
use asn1univ

fn main() [io]
    // `30 03 02 01 07` — a SEQUENCE holding the INTEGER 7, which is the
    // smallest DER document with structure in it.
    let der = bytes.from_hex("3003020107") ?? bytes.zeros(0)
    match asn1read.children_at(der, 0, asn1read.default_limits())
        Ok(kids) =>
            match asn1univ.integer_at(der, kids[0].off, asn1read.default_limits())
                Ok(n)  => println("${n}")   // 7
                Err(e) => println(e.message())
        Err(e)   => println(e.message())
```

## The load-bearing interface

`AsnSpan { off: Int, len: Int }`, and the fact that every reader
answers one rather than a copy.

A certificate's signature is computed over the DER BYTES of its
TBSCertificate, exactly as they arrived — not over a re-encoding of its
values.  A parser that handed back parsed fields and made the caller
rebuild the bytes would produce a different encoding for every
certificate whose writer was not byte-for-byte DER, and the signature
would fail on documents that are perfectly valid.  So
`AsnCertificate.tbs` is a span into the caller's own bytes, and the
caller hashes those.

The same reasoning runs through the rest of the package:
`AsnName.span`, because comparing two names for a chain is comparing
their encodings; `integer_bytes_at`, because a serial number
re-encoded from a number is not the serial number that was signed;
`asn1read.span_bytes` being the one call that allocates, named so a
reader can see where the copy happens.

## DER, and BER where the reference is tolerant

DER is BER with the choices taken away, and every rule it adds exists
for one reason: **one value must have exactly one encoding**, because a
signature is computed over bytes.

Five rules BER allows and DER does not, each with a refusal of its own
name:

| rule | DER | the refusal |
| --- | --- | --- |
| a length in the long form the short form could hold | forbidden | `AsnNonMinimalLength` |
| an indefinite length, `0x80` | forbidden | `AsnIndefiniteLength` |
| a BOOLEAN that is not `0x00` or `0xff` | forbidden | `AsnBadBoolean` |
| an INTEGER with a redundant leading byte | forbidden | `AsnNonMinimalInteger` |
| a SET OF whose elements are not in ascending order | forbidden | `AsnSetOfNotSorted` |

`asn1read.ber_limits()` accepts all five, and `asn1err.is_der_only`
says whether a refusal is one of them.  It is **a flag and not a
default**, because accepting a second encoding is how a signature
checks out over something the reader did not read.  Use it for a file
somebody else's tool wrote when no signature is involved, and not
otherwise.

**The writer has no tolerance flag at all.**  Everything it produces is
DER: the shortest length, the shortest integer, `0xff` for true,
definite lengths throughout, sorted SET OF elements.

One BER rule is **not** lifted by the flag: a UTCTime or
GeneralizedTime without a `Z`.  A certificate that expires at a
different moment in two places is not a thing this package will hand
over.

## The device claim is built

`tests/embedded_probe.nv` compiles `asn1tag` to a Cortex-M4 ELF for
`--target=nrf52-qemu`, and the consumer that makes it worth having is a
device that was provisioned with a public key and is handed a
certificate.  To decide whether to trust what it was sent it walks into
the TBSCertificate, into the SubjectPublicKeyInfo, into the
AlgorithmIdentifier, compares one OBJECT IDENTIFIER and takes the key
bytes.  Every step of that is header arithmetic and arc comparison, and
none of it needs a heap.

`asn1read`, `asn1univ`, `asn1oid`, `asn1write` and `asn1pkix` are
deliberately outside the probe: they speak `Bytes`, `Str` and `Cursor`,
the embedded runtime defines none of them, and one host-only function
anywhere in a compilation unit is an undefined symbol at embedded link
time whether or not the firmware calls it.

## Four things a wrong parser gets wrong quietly

Each is a test in `tests/asn1_tests.nv`.

**The first two OID arcs share one byte, and the division is capped at
2.**  `40 * first + second`, with no limit on the second arc under a
first arc of 2 — so `2.100` packs to 180, and `180 / 40` is 4, which is
not an arc anything has.  A parser without the cap misreads every OID
under the joint arc, which is every X.500 attribute type in a
certificate's subject.  X.690 prints `2.100.3` as the vector for
exactly this.

**An Ed25519 key's algorithm parameters are ABSENT, not NULL.**  RFC
8410 says so explicitly.  A writer that emitted `05 00` there produces
a key half the world refuses.

**An Ed25519 PKCS#8 seed is wrapped twice.**  The `privateKey` OCTET
STRING's content is itself an OCTET STRING holding the thirty-two
bytes.  A parser that skipped the inner one hands over thirty-four
bytes that look nearly right.

**An ECDSA signature is a DER SEQUENCE, not sixty-four bytes.**  Each
half is a shortest-form INTEGER, so an `r` whose top byte is zero is
thirty-one bytes long; a verifier that fed those in unpadded would be
verifying a different number.  `asn1pkix.ecdsa_signature_rs` is the
conversion, and `width` is not optional.

## What this reads, and what it does not

**Reads**: SubjectPublicKeyInfo, PKCS#8 PrivateKeyInfo, an X.509
certificate's fields as values, distinguished names, and four
extensions by name — `basicConstraints`, `keyUsage`,
`subjectAltName`, `extKeyUsage`.  Every other extension is carried as
OID, critical flag and raw value, and
`unknown_critical_extensions` is the one call that answers "is there
anything here I do not understand", which RFC 5280 makes a reason to
refuse.

**Does not**: verify a signature, compute a digest, build a chain, check
revocation, apply name constraints or policy mapping, read a CRL or an
OCSP response.  `ec_public_key_point` hands over exactly what
`p256.public_key_from_bytes` takes and `ed25519_public_key` exactly what
`ed25519.verifying_key_from_bytes` takes; what happens next is those
packages'.  A parser that also verified would be a parser nobody could
audit separately from the arithmetic, and the arithmetic is where the
mistakes live.

**Does not read PEM.**  A `-----BEGIN CERTIFICATE-----` block is base64
with a header, and base64-nv already has the base64; the twenty lines
that strip the armour belong with whichever package reads files.  This
one takes DER bytes.

**Does not read the older `BEGIN EC PRIVATE KEY` form** — SEC 1's
`ECPrivateKey` as a document of its own, rather than inside a PKCS#8
wrapper.  It is one more structure and it is not in this release;
`ec_private_key_scalar` reads the inner one, which is where the same
bytes live when they arrive wrapped.

**Does not read RSA keys.**  There is no RSA row on the grid at all.
`asn1oid.oid_rsa_encryption` is named so a parser can say "this is an
RSA key and nothing here reads one" rather than failing obscurely.

## The layer, and why

`core`.  Everything here is arithmetic over bytes the caller already
holds, and no function declares an effect.  A certificate arrives as
bytes the host read; `is_valid_at` takes the moment as a parameter,
because a `core` package has no clock; a document written comes back as
bytes the host stores.

`asn1read.drain` is the one generic function, and it is `[e]` rather
than `[io]`: it binds the source's effect parameter and is charged
whatever the caller's source costs — nothing for a buffer, `[io]` for a
file (`docs/publishing.md` § How a `core` package takes a stream from
its host).

calendar-nv is the only dependency, and it is what turns UTCTime and
GeneralizedTime into civil dates.  Handing the text over unparsed would
push the two-digit-year rule onto every caller, which is precisely the
rule nobody should have to rediscover.

## The reference implementation

ITU-T X.690 for the encoding, RFC 5280 for the certificate, RFC 5208 and
RFC 5958 for PKCS#8, and RFC 8410 for the Ed25519 forms.  `rasn`
(Rust, MIT) and `asn1crypto` (Python, MIT) are the implementations to
check against.  Every vector in `tests/asn1_tests.nv` is from one of
those documents — the two length forms and the `2.100.3` identifier
from X.690 § 8, the Ed25519 public and private keys decoded from the
base64 RFC 8410 § 10 prints — so a reader can check the port against the
specification rather than against this package.

## Status

| function | implemented |
| --- | --- |
| `asn1err.decode_offset`, `.is_der_only`, the two `message` impls | no |
| `asn1tag.class_*` (four), `.constructed_bit`, `.identifier_byte` | no |
| `asn1tag.class_of`, `.is_constructed`, `.tag_of_low`, `.is_high_tag`, `.identifier_len` | no |
| `asn1tag.tag_*` (fourteen universal numbers) | no |
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
| `asn1oid.oid_*` (seventeen named identifiers) | no |
| `asn1write.tlv_len`, `.context_tlv_len`, `.integer_len`, `.integer_bytes_len` | no |
| `asn1write.oid_len`, `.bit_string_len`, `.sort_set_of` | no |
| `asn1write.write_*_into` (fifteen) | no |
| `asn1write.builder`, `.builder_depth`, `.builder_len`, `.build_limits` | no |
| `asn1write.begin_sequence`, `.begin_set`, `.begin_set_of`, `.begin_explicit`, `.end`, `.done` | no |
| `asn1write.put_*` (eleven) | no |
| `asn1pkix.algorithm_at`, `.spki_at`, `.name_at` | no |
| `asn1pkix.parse_spki`, `.parse_pkcs8`, `.parse_certificate` | no |
| `asn1pkix.extensions_of`, `.extension_by_oid`, `.unknown_critical_extensions` | no |
| `asn1pkix.basic_constraints`, `.key_usage`, `.subject_alt_dns_names`, `.ext_key_usage_oids` | no |
| `asn1pkix.ec_public_key_point`, `.ec_public_key_xy`, `.ec_curve_oid`, `.ec_private_key_scalar` | no |
| `asn1pkix.ed25519_public_key`, `.ed25519_seed` | no |
| `asn1pkix.signature_bytes`, `.ecdsa_signature_rs`, `.ecdsa_signature_der` | no |
| `asn1pkix.algorithms_agree`, `.is_valid_at`, `.name_text`, `.attribute_value`, `.names_encode_equal` | no |
| `asn1pkix.write_spki`, `.write_pkcs8`, `.ec_spki`, `.ed25519_spki` | no |

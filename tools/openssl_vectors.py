#!/usr/bin/env python3
"""Write tests/openssl_tests.nv from certificates and keys OpenSSL makes.

OpenSSL is the oracle.  The script has it generate an EC P-256 key and
an Ed25519 key, a self-signed certificate for each, and the PKCS#8 and
SubjectPublicKeyInfo files of both keys.  The DER of every file goes
into the test file as hex, and OpenSSL's own reading of it goes in as
the expected answers:

1. `openssl asn1parse -i` gives every value's offset, depth, header
   length, content length, construction and tag.  The suite walks the
   same bytes with `asn1read.walk` and compares the lists line for line.
2. `openssl x509` gives the serial number, the subject and issuer in
   RFC 4514 form (`-nameopt RFC2253`), the validity dates, and the four
   named extensions.  `openssl pkey -text` and `openssl ec -text` give
   the raw key bytes.  `openssl asn1parse -strparse` on the signature's
   BIT STRING gives the ECDSA `r` and `s`.
3. The SubjectPublicKeyInfo and PKCS#8 files are written back with
   `asn1pkix.write_spki` and `write_pkcs8`, and must come out byte for
   byte.

The Ed25519 certificate is valid for a hundred years, so its notAfter
is a GeneralizedTime.  The keys are new on every run, so the file is
regenerated only on purpose.

Run from the package root:  python3 tools/openssl_vectors.py
The output is passed through `novo fmt`.
"""
import datetime
import os
import re
import subprocess
import tempfile

TYPES = {
    'SEQUENCE': 'u16', 'SET': 'u17', 'INTEGER': 'u2', 'OBJECT': 'u6', 'BOOLEAN': 'u1',
    'NULL': 'u5', 'BIT STRING': 'u3', 'OCTET STRING': 'u4', 'PRINTABLESTRING': 'u19',
    'UTF8STRING': 'u12', 'IA5STRING': 'u22', 'UTCTIME': 'u23', 'GENERALIZEDTIME': 'u24',
}
LINE = re.compile(r'^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(prim|cons):\s*(.*?)\s*(?::.*)?$')
EKU = {'TLS Web Server Authentication': '1.3.6.1.5.5.7.3.1',
       'TLS Web Client Authentication': '1.3.6.1.5.5.7.3.2'}


def run(*args, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True).stdout


def structure(path):
    out = []
    for line in run('openssl', 'asn1parse', '-inform', 'DER', '-in', path, '-i').decode().splitlines():
        m = LINE.match(line)
        if not m:
            raise SystemExit('unread asn1parse line: %r' % line)
        off, depth, hl, length, kind, rest = m.groups()
        name = rest.split(':')[0].replace('[HEX DUMP]', '').strip()
        ctx = re.match(r'cont \[ (\d+) \]', name)
        if ctx:
            tag = 'c' + ctx.group(1)
        elif name in TYPES:
            tag = TYPES[name]
        else:
            raise SystemExit('unknown asn1parse type %r' % name)
        out.append('%s:%s:%s:%s:%s:%s' % (off, depth, hl, length, kind[0], tag))
    return out


def colon_hex(text, label):
    m = re.search(label + r':\s*\n((?:\s+[0-9a-f:]+\n?)+)', text)
    return m.group(1).replace(':', '').replace(' ', '').replace('\n', '')


def x509(path, *flags):
    return run('openssl', 'x509', '-inform', 'DER', '-in', path, '-noout', *flags).decode()


def when(text):
    t = datetime.datetime.strptime(' '.join(text.split()), '%b %d %H:%M:%S %Y GMT')
    return '%d, %d, %d, %d, %d, %d' % (t.year, t.month, t.day, t.hour, t.minute, t.second)


def lit_list(xs):
    return '[' + ', '.join('"%s"' % x for x in xs) + ']'


def der_fn(name, path, comment):
    hexs = open(path, 'rb').read().hex()
    return '// %s\nfn %s() -> Bytes\n    bytes.from_hex("%s") ?? bytes.zeros(0)\n' % (comment, name, hexs)


work = tempfile.mkdtemp()
p = lambda n: os.path.join(work, n)

run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', p('ec.pem'))
run('openssl', 'req', '-new', '-x509', '-key', p('ec.pem'), '-days', '400', '-sha256',
    '-subj', '/C=GB/O=Acme Ltd/OU=Research, North/CN=example.com',
    '-addext', 'subjectAltName=DNS:example.com,DNS:www.example.com,email:admin@example.com',
    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:1',
    '-addext', 'keyUsage=critical,digitalSignature,keyCertSign',
    '-addext', 'extendedKeyUsage=serverAuth,clientAuth',
    '-outform', 'DER', '-out', p('ec_cert.der'))
run('openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', p('ec.pem'), '-outform', 'DER', '-out', p('ec_pkcs8.der'))
run('openssl', 'pkey', '-in', p('ec.pem'), '-pubout', '-outform', 'DER', '-out', p('ec_spki.der'))
run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', p('ed.pem'))
run('openssl', 'req', '-new', '-x509', '-key', p('ed.pem'), '-days', '36500',
    '-subj', '/CN=device-7/O=Acme Ltd', '-addext', 'subjectAltName=DNS:device-7.example.com',
    '-outform', 'DER', '-out', p('ed_cert.der'))
run('openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', p('ed.pem'), '-outform', 'DER', '-out', p('ed_pkcs8.der'))
run('openssl', 'pkey', '-in', p('ed.pem'), '-pubout', '-outform', 'DER', '-out', p('ed_spki.der'))

ec_text = run('openssl', 'ec', '-in', p('ec.pem'), '-text', '-noout').decode()
ed_text = run('openssl', 'pkey', '-in', p('ed.pem'), '-text', '-noout').decode()

out = []
emit = out.append
emit('''// openssl_tests.nv — certificates and keys made by OpenSSL, read here
// and compared with OpenSSL's own reading of them.
//
// Written by tools/openssl_vectors.py; do not edit by hand.  The
// script's docstring says what each comparison takes from OpenSSL.

use std.test
use std.bytes
use std.str
use asn1read
use asn1univ
use asn1oid
use asn1pkix
use civil

// Every value of a document, one line each, in the form
// `openssl asn1parse` prints: offset, depth, header length, content
// length, `p` or `c`, and the tag as `u` or `c` and its number.
fn structure(der: Bytes) -> [Str]
    let lim = asn1read.default_limits()
    var out: [Str] = []
    var depth = 0
    match asn1read.walk(der, lim)
        Ok(events) =>
            for ev in events
                match ev
                    AsnConstructedStart(t, at, length) =>
                        list.push(out, line(der, at, depth, length, "c", t))
                        depth = depth + 1
                    AsnPrimitiveValue(t, at, content)  =>
                        list.push(out, line(der, at, depth, bytes.len(content), "p", t))
                    AsnConstructedEnd(_, _)            =>
                        depth = depth - 1
        Err(e)     => test.fail(e.message())
    out

fn line(der: Bytes, at: Int, depth: Int, length: Int, kind: Str, t: AsnTag) -> Str
    let hl = match asn1read.header_at(der, at, asn1read.default_limits())
        Ok(h)  => h.header_len
        Err(_) => -1
    let class = if t.class == AsnContext then "c" else "u"
    "${at}:${depth}:${hl}:${length}:${kind}:${class}${t.number}"

fn instant(y: Int, mo: Int, d: Int, h: Int, mi: Int, s: Int) -> CivilDateTime
    let Ok(day) = civil.date(y, mo, d) else return civil.datetime(civil.date_from_epoch_day(0), civil.midnight())
    let Ok(time) = civil.time_of(h, mi, s, 0) else return civil.datetime(day, civil.midnight())
    civil.datetime(day, time)

fn same(a: CivilDateTime, b: CivilDateTime) -> Bool
    civil.compare_datetime(a, b) == 0

// The hex of written bytes, or the refusal's message.
fn hex_of(r: Result<Bytes, AsnEncodeError>) -> Str
    match r
        Ok(b)  => bytes.to_hex(b)
        Err(e) => e.message()

fn dns_of(c: AsnCertificate) -> [Str]
    match asn1pkix.subject_alt_dns_names(c, asn1read.default_limits())
        Ok(names) => names
        Err(e)    => [e.message()]

// An integer's hex with its leading zeros gone, which is how OpenSSL
// prints a serial number.
fn trimmed(h: Str) -> Str
    var s = h
    while str.len(s) > 2 and str.starts_with(s, "00")
        s = str.slice(s, 2, str.len(s))
    s
''')

files = [('ec_cert', 'ec_cert.der', 'An EC P-256 certificate OpenSSL signed for itself.'),
         ('ec_pkcs8', 'ec_pkcs8.der', 'Its private key, as PKCS#8.'),
         ('ec_spki', 'ec_spki.der', 'Its public key, as a SubjectPublicKeyInfo.'),
         ('ed_cert', 'ed_cert.der', 'An Ed25519 certificate valid for a hundred years.'),
         ('ed_pkcs8', 'ed_pkcs8.der', 'Its private key, as PKCS#8.'),
         ('ed_spki', 'ed_spki.der', 'Its public key, as a SubjectPublicKeyInfo.')]
for name, f, comment in files:
    emit(der_fn(name, p(f), comment))
for name, f, _ in files:
    emit('@test\nfn test_%s_walks_as_openssl_asn1parse_reads_it()' % name)
    emit('    test.assert_eq(structure(%s()), %s)\n' % (name, lit_list(structure(p(f)))))

for name in ('ec_cert', 'ed_cert'):
    f = p(name + '.der')
    serial = x509(f, '-serial').split('=', 1)[1].strip().lower()
    subject = x509(f, '-nameopt', 'RFC2253', '-subject').split('=', 1)[1].strip()
    issuer = x509(f, '-nameopt', 'RFC2253', '-issuer').split('=', 1)[1].strip()
    start = x509(f, '-startdate').split('=', 1)[1].strip()
    end = x509(f, '-enddate').split('=', 1)[1].strip()
    san = x509(f, '-ext', 'subjectAltName').splitlines()[1].strip()
    dns = [x.split(':', 1)[1] for x in san.split(', ') if x.startswith('DNS:')]
    tbs = structure(f)[1].split(':')
    emit('@test\nfn test_%s_fields_match_openssl_x509()' % name)
    emit('    match asn1pkix.parse_certificate(%s(), asn1read.default_limits())' % name)
    emit('        Err(e) => test.fail(e.message())')
    emit('        Ok(c)  =>')
    emit('            test.assert_eq(c.version, 3)')
    emit('            test.assert_eq(trimmed(bytes.to_hex(c.serial)), trimmed("%s"))' % serial)
    emit('            test.assert_eq(asn1pkix.name_text(c.subject), "%s")' % subject.replace('\\', '\\\\'))
    emit('            test.assert_eq(asn1pkix.name_text(c.issuer), "%s")' % issuer.replace('\\', '\\\\'))
    emit('            test.assert(same(c.not_before, instant(%s)))' % when(start))
    emit('            test.assert(same(c.not_after, instant(%s)))' % when(end))
    emit('            test.assert_eq(c.tbs.off, %s)' % tbs[0])
    emit('            test.assert_eq(c.tbs.len, %d)' % (int(tbs[2]) + int(tbs[3])))
    emit('            test.assert(asn1pkix.algorithms_agree(c))')
    emit('            test.assert(asn1pkix.names_encode_equal(%s(), c.subject, %s(), c.issuer))' % (name, name))
    emit('            test.assert_eq(dns_of(c), %s)' % lit_list(dns))
    if name == 'ec_cert':
        eku = x509(f, '-ext', 'extendedKeyUsage').splitlines()[1].strip().split(', ')
        emit('            test.assert_eq(asn1pkix.unknown_critical_extensions(c).len(), 0)')
        emit('            match asn1pkix.basic_constraints(c, asn1read.default_limits())')
        emit('                Ok(Some(b)) =>')
        emit('                    test.assert(b.is_ca)')
        emit('                    test.assert_eq(b.path_len, 1)')
        emit('                _           => test.fail("basicConstraints was not read")')
        emit('            match asn1pkix.key_usage(c, asn1read.default_limits())')
        emit('                Ok(Some(k)) =>')
        emit('                    test.assert(asn1univ.bit_at(k, 0))')
        emit('                    test.assert(asn1univ.bit_at(k, 5))')
        emit('                    test.assert(not asn1univ.bit_at(k, 1))')
        emit('                _           => test.fail("keyUsage was not read")')
        emit('            match asn1pkix.ext_key_usage_oids(c, asn1read.default_limits())')
        emit('                Ok(os) =>')
        emit('                    var texts: [Str] = []')
        emit('                    for o in os')
        emit('                        list.push(texts, asn1oid.oid_text(o))')
        emit('                    test.assert_eq(texts, %s)' % lit_list([EKU[x] for x in eku]))
        emit('                Err(e) => test.fail(e.message())')
        emit('            match asn1pkix.ec_public_key_point(c.public_key)')
        emit('                Ok(pt) => test.assert_eq(bytes.to_hex(pt), "%s")' % colon_hex(ec_text, 'pub'))
        emit('                Err(e) => test.fail(e.message())')
        sig_off = structure(f)[-1].split(':')[0]
        rs = run('openssl', 'asn1parse', '-inform', 'DER', '-in', f, '-strparse', sig_off).decode()
        ints = re.findall(r'INTEGER\s*:([0-9A-F]+)', rs)
        emit('            match asn1pkix.signature_bytes(c)')
        emit('                Ok(sig) =>')
        emit('                    match asn1pkix.ecdsa_signature_rs(sig, 32, asn1read.default_limits())')
        emit('                        Ok(p)  =>')
        emit('                            test.assert_eq(bytes.to_hex(p.r), "%s")' % ints[0].lower().rjust(64, '0')[-64:])
        emit('                            test.assert_eq(bytes.to_hex(p.s), "%s")' % ints[1].lower().rjust(64, '0')[-64:])
        emit('                            test.assert_eq(hex_of(asn1pkix.ecdsa_signature_der(p.r, p.s)), bytes.to_hex(sig))')
        emit('                        Err(e) => test.fail(e.message())')
        emit('                Err(e)  => test.fail(e.message())')
    else:
        emit('            match asn1pkix.ed25519_public_key(c.public_key)')
        emit('                Ok(k)  => test.assert_eq(bytes.to_hex(k), "%s")' % colon_hex(ed_text, 'pub'))
        emit('                Err(e) => test.fail(e.message())')
    emit('')

emit('@test\nfn test_the_keys_match_openssl_pkey_and_write_back_byte_for_byte()')
emit('    let lim = asn1read.default_limits()')
for name in ('ec_spki', 'ed_spki'):
    emit('    match asn1pkix.parse_spki(%s(), lim)' % name)
    emit('        Ok(k)  => test.assert_eq(hex_of(asn1pkix.write_spki(k)), bytes.to_hex(%s()))' % name)
    emit('        Err(e) => test.fail(e.message())')
for name in ('ec_pkcs8', 'ed_pkcs8'):
    emit('    match asn1pkix.parse_pkcs8(%s(), lim)' % name)
    emit('        Ok(k)  =>')
    emit('            test.assert_eq(hex_of(asn1pkix.write_pkcs8(k)), bytes.to_hex(%s()))' % name)
    if name == 'ec_pkcs8':
        emit('            match asn1pkix.ec_private_key_scalar(k)')
        emit('                Ok(d)  => test.assert_eq(bytes.to_hex(d), "%s")' % colon_hex(ec_text, 'priv').rjust(64, '0'))
    else:
        emit('            match asn1pkix.ed25519_seed(k)')
        emit('                Ok(d)  => test.assert_eq(bytes.to_hex(d), "%s")' % colon_hex(ed_text, 'priv'))
    emit('                Err(e) => test.fail(e.message())')
    emit('        Err(e) => test.fail(e.message())')

path = 'tests/openssl_tests.nv'
open(path, 'w').write('\n'.join(out) + '\n')
subprocess.run(['novo', 'fmt', path], check=False)

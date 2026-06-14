// Minimal ASN.1 DER encoder/decoder for building PKCS#7 (CMS) SignedData.
//
// Implements just enough of ITU-T X.690 DER (a public standard) to:
//   - encode the TLV primitives a detached CMS SignedData needs, and
//   - extract the issuer (raw DER) + serialNumber from an X.509 cert.
//
// This replaces the former `pkijs` + `asn1js` runtime dependencies so the
// library ships with zero runtime dependencies. node:crypto handles the
// RSA signing and X.509 parsing; this module only does the byte plumbing.

// ─── DER length + TLV ─────────────────────────────────────────────────────

export function encodeLength(length: number): Buffer {
  if (length < 0x80) return Buffer.from([length]);
  const bytes: number[] = [];
  let n = length;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([tag]),
    encodeLength(content.length),
    content,
  ]);
}

// Wrap an already-encoded TLV element verbatim (used to re-emit parsed
// substructures such as a certificate issuer).
export function raw(value: Buffer | Uint8Array): Buffer {
  return Buffer.from(value);
}

// ─── DER constructors ─────────────────────────────────────────────────────

export function sequence(...values: Buffer[]): Buffer {
  return tlv(0x30, Buffer.concat(values));
}

// SET OF (tag 0x31). Per DER (X.690 §11.6) the elements of a SET OF are
// sorted by their full encoding, compared as unsigned byte strings. We
// sort here so the output is canonical regardless of the caller's order.
export function set(...values: Buffer[]): Buffer {
  const sorted = values.toSorted((a, b) => Buffer.compare(a, b));
  return tlv(0x31, Buffer.concat(sorted));
}

// Context-specific [n] constructed wrapper (tag 0xA0 | n). Used both as an
// EXPLICIT wrapper (e.g. ContentInfo.content [0]) and as an IMPLICIT tag
// replacing a SET/SEQUENCE (e.g. SignerInfo.signedAttrs [0], SignedData
// .certificates [0]). The caller decides the semantics by what it passes.
export function contextConstructed(n: number, ...values: Buffer[]): Buffer {
  return tlv(0xa0 | n, Buffer.concat(values));
}

export function octetString(value: Buffer | Uint8Array): Buffer {
  return tlv(0x04, Buffer.from(value));
}

export function nullValue(): Buffer {
  return Buffer.from([0x05, 0x00]);
}

export function integer(value: number | bigint): Buffer {
  let n = typeof value === 'bigint' ? value : BigInt(value);
  if (n < 0n) throw new RangeError('negative integers are not supported');
  const bytes: number[] = [];
  if (n === 0n) {
    bytes.push(0);
  } else {
    while (n > 0n) {
      bytes.unshift(Number(n & 0xffn));
      n >>= 8n;
    }
    // Pad with a leading zero if the high bit is set (keep it positive).
    if (bytes[0]! & 0x80) bytes.unshift(0);
  }
  return tlv(0x02, Buffer.from(bytes));
}

// Encode an INTEGER from an existing big-endian byte buffer (e.g. a cert
// serial number lifted straight out of the certificate DER).
export function integerFromBytes(bytes: Buffer): Buffer {
  let b = bytes;
  // Strip leading zero bytes that aren't needed to keep the sign positive.
  let start = 0;
  while (
    start < b.length - 1 &&
    b[start] === 0 &&
    (b[start + 1]! & 0x80) === 0
  ) {
    start++;
  }
  b = b.subarray(start);
  if (b.length === 0) b = Buffer.from([0]);
  if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
}

export function objectIdentifier(oid: string): Buffer {
  const parts = oid.split('.').map(p => BigInt(p));
  if (parts.length < 2) throw new TypeError(`invalid OID: ${oid}`);
  const bytes: number[] = [];
  // First two arcs are combined: 40*X + Y.
  bytes.push(...encodeBase128(parts[0]! * 40n + parts[1]!));
  for (let i = 2; i < parts.length; i++)
    bytes.push(...encodeBase128(parts[i]!));
  return tlv(0x06, Buffer.from(bytes));
}

function encodeBase128(value: bigint): number[] {
  if (value < 0n) throw new RangeError('OID arc must be non-negative');
  const out: number[] = [];
  let n = value;
  do {
    out.unshift(Number(n & 0x7fn));
    n >>= 7n;
  } while (n > 0n);
  // All but the last byte have the continuation bit set.
  for (let i = 0; i < out.length - 1; i++) out[i]! |= 0x80;
  return out;
}

// CMS "Time" (RFC 5652 §11.3): UTCTime for years 1950–2049, otherwise
// GeneralizedTime. Both are encoded in UTC with seconds, per DER rules
// (X.690 §11.7/§11.8: no fractional seconds, 'Z' zone, two-digit fields).
export function time(date: Date): Buffer {
  const year = date.getUTCFullYear();
  const mm = pad2(date.getUTCMonth() + 1);
  const dd = pad2(date.getUTCDate());
  const hh = pad2(date.getUTCHours());
  const mi = pad2(date.getUTCMinutes());
  const ss = pad2(date.getUTCSeconds());
  if (year >= 1950 && year < 2050) {
    // UTCTime: YYMMDDHHMMSSZ
    const s = pad2(year % 100) + mm + dd + hh + mi + ss + 'Z';
    return tlv(0x17, Buffer.from(s, 'ascii'));
  }
  // GeneralizedTime: YYYYMMDDHHMMSSZ
  const s = year.toString().padStart(4, '0') + mm + dd + hh + mi + ss + 'Z';
  return tlv(0x18, Buffer.from(s, 'ascii'));
}

function pad2(n: number): string {
  return n.toString().padStart(2, '0');
}

// ─── X.509 reader ─────────────────────────────────────────────────────────

interface DerElement {
  tag: number;
  // Full TLV (tag + length + content), as it appears in the source.
  full: Buffer;
  // Just the content (value) bytes.
  content: Buffer;
  // Offset in the parent buffer immediately past this element.
  end: number;
}

function readElement(buf: Buffer, offset: number): DerElement {
  if (offset + 2 > buf.length) throw new Error('DER: truncated element header');
  const tag = buf[offset]!;
  let i = offset + 1;
  const first = buf[i++]!;
  let length: number;
  if (first < 0x80) {
    length = first;
  } else {
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4)
      throw new Error('DER: unsupported length encoding');
    if (i + numBytes > buf.length)
      throw new Error('DER: truncated length field');
    length = 0;
    for (let k = 0; k < numBytes; k++) length = length * 256 + buf[i++]!;
  }
  const end = i + length;
  if (end > buf.length) throw new Error('DER: element length exceeds buffer');
  const content = buf.subarray(i, end);
  return { tag, full: buf.subarray(offset, end), content, end };
}

export interface CertificateInfo {
  // Raw DER of the issuer Name (a SEQUENCE), re-emittable verbatim.
  issuer: Buffer;
  // Raw big-endian serialNumber INTEGER content bytes.
  serialNumber: Buffer;
}

// Parse just the fields of a certificate we need for IssuerAndSerialNumber.
// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
// TBSCertificate ::= SEQUENCE {
//   [0] version OPTIONAL, serialNumber INTEGER, signature, issuer Name, ... }
export function extractCertificateInfo(certDer: Buffer): CertificateInfo {
  const cert = readElement(certDer, 0);
  if (cert.tag !== 0x30) throw new Error('certificate: expected SEQUENCE');
  const tbs = readElement(cert.content, 0);
  if (tbs.tag !== 0x30)
    throw new Error('certificate: expected tbsCertificate SEQUENCE');

  let pos = 0;
  // Optional [0] EXPLICIT version.
  let el = readElement(tbs.content, pos);
  if (el.tag === 0xa0) {
    pos = el.end;
    el = readElement(tbs.content, pos);
  }
  // serialNumber INTEGER
  if (el.tag !== 0x02)
    throw new Error('certificate: expected serialNumber INTEGER');
  const serialNumber = Buffer.from(el.content);
  pos = el.end;
  // signature AlgorithmIdentifier (SEQUENCE) — skip.
  el = readElement(tbs.content, pos);
  pos = el.end;
  // issuer Name (SEQUENCE) — capture full TLV.
  el = readElement(tbs.content, pos);
  if (el.tag !== 0x30)
    throw new Error('certificate: expected issuer Name SEQUENCE');
  const issuer = Buffer.from(el.full);

  return { issuer, serialNumber };
}

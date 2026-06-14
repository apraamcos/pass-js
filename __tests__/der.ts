import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  integer,
  integerFromBytes,
  encodeLength,
  objectIdentifier,
  sequence,
  set,
  octetString,
  nullValue,
  contextConstructed,
  time,
  extractCertificateInfo,
} from '../dist/lib/der.js';

const hex = (b: Buffer): string => Buffer.from(b).toString('hex');

describe('der', () => {
  it('encodes INTEGER with positive-sign padding', () => {
    assert.equal(hex(integer(0)), '020100');
    assert.equal(hex(integer(127)), '02017f');
    assert.equal(hex(integer(128)), '02020080'); // high bit → leading zero
    assert.equal(hex(integer(255)), '020200ff');
    assert.equal(hex(integer(256)), '02020100');
  });

  it('encodes INTEGER from raw big-endian bytes', () => {
    assert.equal(hex(integerFromBytes(Buffer.from([0x80]))), '02020080');
    assert.equal(hex(integerFromBytes(Buffer.from([0x00, 0x7f]))), '02017f');
    assert.equal(hex(integerFromBytes(Buffer.from([0x12, 0x34]))), '02021234');
  });

  it('encodes definite-form lengths', () => {
    assert.equal(hex(encodeLength(127)), '7f');
    assert.equal(hex(encodeLength(128)), '8180');
    assert.equal(hex(encodeLength(256)), '820100');
  });

  it('encodes OBJECT IDENTIFIER (base-128)', () => {
    // id-signedData
    assert.equal(
      hex(objectIdentifier('1.2.840.113549.1.7.2')),
      '06092a864886f70d010702',
    );
    // sha1
    assert.equal(hex(objectIdentifier('1.3.14.3.2.26')), '06052b0e03021a');
  });

  it('wraps SEQUENCE / SET / [0] / OCTET STRING / NULL', () => {
    assert.equal(hex(sequence(integer(1))), '3003020101');
    assert.equal(hex(set(integer(1))), '3103020101');
    assert.equal(hex(contextConstructed(0, integer(1))), 'a003020101');
    assert.equal(hex(octetString(Buffer.from([0xde, 0xad]))), '0402dead');
    assert.equal(hex(nullValue()), '0500');
  });

  it('encodes CMS Time as UTCTime before 2050, GeneralizedTime after', () => {
    // 2024-01-02T03:04:05Z → UTCTime "240102030405Z"
    const utc = time(new Date(Date.UTC(2024, 0, 2, 3, 4, 5)));
    assert.equal(utc[0], 0x17); // UTCTime tag
    assert.equal(utc.subarray(2).toString('ascii'), '240102030405Z');

    // 2050-01-02T03:04:05Z → GeneralizedTime "20500102030405Z"
    const gen = time(new Date(Date.UTC(2050, 0, 2, 3, 4, 5)));
    assert.equal(gen[0], 0x18); // GeneralizedTime tag
    assert.equal(gen.subarray(2).toString('ascii'), '20500102030405Z');
  });

  it('rejects truncated / malformed DER when parsing a certificate', () => {
    assert.throws(() => extractCertificateInfo(Buffer.from([0x30])), /DER/);
    // SEQUENCE claiming 10 bytes but only 1 present.
    assert.throws(
      () => extractCertificateInfo(Buffer.from([0x30, 0x0a, 0x00])),
      /DER/,
    );
  });

  it('extracts issuer + serialNumber from an X.509 DER', () => {
    // Minimal hand-built TBSCertificate inside a Certificate SEQUENCE:
    //   Certificate ::= SEQUENCE { tbs, sigAlg, sig }
    //   tbs ::= SEQUENCE { [0] version, serial INTEGER, sigAlg, issuer Name }
    const version = contextConstructed(0, integer(2)); // v3
    const serial = integer(0x1234);
    const innerSigAlg = sequence(objectIdentifier('1.2.840.113549.1.1.11'));
    const issuer = sequence(
      set(
        sequence(objectIdentifier('2.5.4.3'), octetString(Buffer.from('CA'))),
      ),
    );
    const tbs = sequence(version, serial, innerSigAlg, issuer);
    const cert = sequence(tbs, innerSigAlg, octetString(Buffer.from([0x00])));

    const info = extractCertificateInfo(cert);
    assert.equal(hex(info.issuer), hex(issuer));
    assert.equal(hex(info.serialNumber), '1234');
  });

  it('round-trips a serial number whose high bit is set', () => {
    // INTEGER 0x00C0FFEE — the leading 0x00 keeps it positive on the wire,
    // and extractCertificateInfo must preserve the content bytes verbatim so
    // integerFromBytes can re-pad them identically.
    const serial = Buffer.from([0x00, 0xc0, 0xff, 0xee]);
    const serialEl = Buffer.concat([
      Buffer.from([0x02, serial.length]),
      serial,
    ]);
    const version = contextConstructed(0, integer(2));
    const innerSigAlg = sequence(objectIdentifier('1.2.840.113549.1.1.11'));
    const issuer = sequence(
      set(
        sequence(objectIdentifier('2.5.4.3'), octetString(Buffer.from('CA'))),
      ),
    );
    const tbs = sequence(version, serialEl, innerSigAlg, issuer);
    const cert = sequence(tbs, innerSigAlg, octetString(Buffer.from([0x00])));

    const info = extractCertificateInfo(cert);
    assert.equal(hex(info.serialNumber), '00c0ffee');
    // re-encoding keeps the positive-sign leading zero
    assert.equal(hex(integerFromBytes(info.serialNumber)), '020400c0ffee');
  });

  it('SET OF sorts members into DER canonical order', () => {
    // Two elements given out of order must come back byte-sorted.
    const a = octetString(Buffer.from([0x01]));
    const b = octetString(Buffer.from([0x02]));
    assert.equal(hex(set(b, a)), hex(set(a, b)));
    assert.equal(hex(set(b, a)).startsWith('31'), true);
  });
});

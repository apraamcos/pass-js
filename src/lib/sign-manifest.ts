import {
  createHash,
  createSign,
  createPrivateKey,
  X509Certificate,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';

import {
  sequence,
  set,
  contextConstructed,
  octetString,
  nullValue,
  integer,
  integerFromBytes,
  objectIdentifier,
  time,
  raw,
  extractCertificateInfo,
} from './der.js';

// Return the DER bytes of a PEM (or DER) X.509 certificate via node:crypto.
function certificateDer(pem: string): Buffer {
  return Buffer.from(new X509Certificate(pem).raw);
}

// Apple WWDR Certification Authority — G4
// Valid: 2020-12-16 through 2030-12-10
// Source: https://www.apple.com/certificateauthority/AppleWWDRCAG4.cer
// SHA-256 fingerprint: EA:47:57:88:55:38:DD:8C:B5:9F:F4:55:6F:67:60:87:D8:3C:85:E7:09:02:C1:22:E4:2C:08:08:B5:BC:E1:4C
const APPLE_WWDR_G4_PEM = `-----BEGIN CERTIFICATE-----
MIIEVTCCAz2gAwIBAgIUE9x3lVJx5T3GMujM/+Uh88zFztIwDQYJKoZIhvcNAQEL
BQAwYjELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsT
HUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBS
b290IENBMB4XDTIwMTIxNjE5MzYwNFoXDTMwMTIxMDAwMDAwMFowdTFEMEIGA1UE
Aww7QXBwbGUgV29ybGR3aWRlIERldmVsb3BlciBSZWxhdGlvbnMgQ2VydGlmaWNh
dGlvbiBBdXRob3JpdHkxCzAJBgNVBAsMAkc0MRMwEQYDVQQKDApBcHBsZSBJbmMu
MQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANAf
eKp6JzKwRl/nF3bYoJ0OKY6tPTKlxGs3yeRBkWq3eXFdDDQEYHX3rkOPR8SGHgjo
v9Y5Ui8eZ/xx8YJtPH4GUnadLLzVQ+mxtLxAOnhRXVGhJeG+bJGdayFZGEHVD41t
QSo5SiHgkJ9OE0/QjJoyuNdqkh4laqQyziIZhQVg3AJK8lrrd3kCfcCXVGySjnYB
5kaP5eYq+6KwrRitbTOFOCOL6oqW7Z+uZk+jDEAnbZXQYojZQykn/e2kv1MukBVl
PNkuYmQzHWxq3Y4hqqRfFcYw7V/mjDaSlLfcOQIA+2SM1AyB8j/VNJeHdSbCb64D
YyEMe9QbsWLFApy9/a8CAwEAAaOB7zCB7DASBgNVHRMBAf8ECDAGAQH/AgEAMB8G
A1UdIwQYMBaAFCvQaUeUdgn+9GuNLkCm90dNfwheMEQGCCsGAQUFBwEBBDgwNjA0
BggrBgEFBQcwAYYoaHR0cDovL29jc3AuYXBwbGUuY29tL29jc3AwMy1hcHBsZXJv
b3RjYTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vY3JsLmFwcGxlLmNvbS9yb290
LmNybDAdBgNVHQ4EFgQUW9n6HeeaGgujmXYiUIY+kchbd6gwDgYDVR0PAQH/BAQD
AgEGMBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQA/Vj2e5bbD
eeZFIGi9v3OLLBKeAuOugCKMBB7DUshwgKj7zqew1UJEggOCTwb8O0kU+9h0UoWv
p50h5wESA5/NQFjQAde/MoMrU1goPO6cn1R2PWQnxn6NHThNLa6B5rmluJyJlPef
x4elUWY0GzlxOSTjh2fvpbFoe4zuPfeutnvi0v/fYcZqdUmVIkSoBPyUuAsuORFJ
EtHlgepZAE9bPFo22noicwkJac3AfOriJP6YRLj477JxPxpd1F1+M02cHSS+APCQ
A1iZQT0xWmJArzmoUUOSqwSonMJNsUvSq3xKX+udO7xPiEAGE/+QF4oIRynoYpgp
pU8RBWk6z/Kf
-----END CERTIFICATE-----`;

// Override via env for dev/test only.
const APPLE_WWDR_CA_PEM =
  process.env['APPLE_WWDR_CERT_PEM'] || APPLE_WWDR_G4_PEM;

// OIDs Apple requires in the PKCS#7 SignedData.
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_SHA1 = '1.3.14.3.2.26';
const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';

const APPLE_WWDR_CA = new X509Certificate(APPLE_WWDR_CA_PEM);
const APPLE_WWDR_CA_DER = Buffer.from(APPLE_WWDR_CA.raw);

// Emit a process warning if the bundled WWDR cert is within 90 days of
// expiry (or already expired). The 2013–2023 G1 silently expired and every
// downstream user shipped broken passes for months before anyone noticed —
// this is the guard that should catch the next rotation.
//
// Uses process.emitWarning (rather than console.warn) so consumers can
// silence or intercept it the standard Node way:
//   node --disable-warning=WalletPassWWDRExpiring app.js
//   process.on('warning', w => { if (w.code === 'WALLETPASS_WWDR_EXPIRED') ... })
const WWDR_WARN_WINDOW_MS = 90 * 24 * 60 * 60 * 1000;
const wwdrNotAfter = new Date(APPLE_WWDR_CA.validTo);
const msUntilExpiry = wwdrNotAfter.getTime() - Date.now();
if (msUntilExpiry < WWDR_WARN_WINDOW_MS) {
  const when = wwdrNotAfter.toISOString().slice(0, 10);
  const days = Math.ceil(msUntilExpiry / (24 * 60 * 60 * 1000));
  if (msUntilExpiry < 0) {
    process.emitWarning(
      `Bundled Apple WWDR certificate expired on ${when}. Signed passes will fail validation. Upgrade @walletpass/pass-js or override via APPLE_WWDR_CERT_PEM. See https://www.apple.com/certificateauthority/`,
      { type: 'WalletPassWWDRExpired', code: 'WALLETPASS_WWDR_EXPIRED' },
    );
  } else {
    process.emitWarning(
      `Bundled Apple WWDR certificate expires on ${when} (${days} days). Upgrade @walletpass/pass-js before then to avoid silently shipping invalid passes.`,
      { type: 'WalletPassWWDRExpiring', code: 'WALLETPASS_WWDR_EXPIRING' },
    );
  }
}

// ─── Public API ─────────────────────────────────────────────────────────────

// Sign the manifest.json of an Apple Wallet pass bundle.
// Returns a detached PKCS#7 (CMS) SignedData DER blob suitable for the
// pkpass `signature` file.
//
// - `certificatePem`: the Pass Type ID signing certificate (PEM).
// - `privateKey`: the matching RSA private key as a PEM string or
//   a node:crypto KeyObject. Pass a password via `createPrivateKey`
//   before calling if the key is encrypted.
// - `manifestJson`: the manifest.json contents to sign (string).
export function signManifest(
  certificatePem: string,
  privateKey: string | KeyObject,
  manifestJson: string,
): Buffer {
  const signerCertDer = certificateDer(certificatePem);
  const { issuer, serialNumber } = extractCertificateInfo(signerCertDer);

  const keyObject =
    typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey;

  const manifestBytes = Buffer.from(manifestJson, 'utf8');
  const digest = createHash('sha1').update(manifestBytes).digest();

  // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
  const sha1Algorithm = sequence(objectIdentifier(OID_SHA1), nullValue());
  const rsaAlgorithm = sequence(
    objectIdentifier(OID_RSA_ENCRYPTION),
    nullValue(),
  );

  // Each signed attribute: SEQUENCE { attrType OID, attrValues SET OF ... }
  const attrContentType = sequence(
    objectIdentifier(OID_CONTENT_TYPE),
    set(objectIdentifier(OID_DATA)),
  );
  const attrMessageDigest = sequence(
    objectIdentifier(OID_MESSAGE_DIGEST),
    set(octetString(digest)),
  );
  const attrSigningTime = sequence(
    objectIdentifier(OID_SIGNING_TIME),
    set(time(new Date())),
  );

  // The signed bytes are the SignedAttributes as an EXPLICIT SET OF (tag
  // 0x31, DER-sorted), per RFC 5652 §5.4. The very same encoding appears in
  // the SignerInfo as an IMPLICIT [0] (tag 0xA0) — identical content/length,
  // only the leading tag byte differs. Deriving one from the other keeps the
  // signed bytes and the on-wire bytes byte-for-byte consistent.
  const signedAttrsForSigning = set(
    attrContentType,
    attrMessageDigest,
    attrSigningTime,
  );
  const signedAttrsImplicit = Buffer.concat([
    Buffer.from([0xa0]),
    signedAttrsForSigning.subarray(1),
  ]);

  const signature = createSign('sha1')
    .update(signedAttrsForSigning)
    .sign(keyObject);

  // SignerInfo ::= SEQUENCE {
  //   version INTEGER (1),
  //   sid IssuerAndSerialNumber,
  //   digestAlgorithm AlgorithmIdentifier,
  //   signedAttrs [0] IMPLICIT SET OF Attribute,
  //   signatureAlgorithm AlgorithmIdentifier,
  //   signature OCTET STRING }
  const issuerAndSerial = sequence(raw(issuer), integerFromBytes(serialNumber));
  const signerInfo = sequence(
    integer(1),
    issuerAndSerial,
    sha1Algorithm,
    signedAttrsImplicit,
    rsaAlgorithm,
    octetString(signature),
  );

  // SignedData ::= SEQUENCE {
  //   version INTEGER (1),
  //   digestAlgorithms SET OF AlgorithmIdentifier,
  //   encapContentInfo EncapsulatedContentInfo,
  //   certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
  //   signerInfos SET OF SignerInfo }
  const encapContentInfo = sequence(objectIdentifier(OID_DATA)); // detached: no eContent
  // certificates [0] IMPLICIT SET OF Certificate. Build a DER-sorted SET
  // then swap the leading SET tag (0x31) for the IMPLICIT [0] tag (0xA0).
  const certificatesSet = set(raw(signerCertDer), APPLE_WWDR_CA_DER);
  const certificates = Buffer.concat([
    Buffer.from([0xa0]),
    certificatesSet.subarray(1),
  ]);
  const signedData = sequence(
    integer(1),
    set(sha1Algorithm),
    encapContentInfo,
    certificates,
    set(signerInfo),
  );

  // ContentInfo ::= SEQUENCE {
  //   contentType OID (id-signedData),
  //   content [0] EXPLICIT SignedData }
  const contentInfo = sequence(
    objectIdentifier(OID_SIGNED_DATA),
    contextConstructed(0, signedData),
  );

  return contentInfo;
}

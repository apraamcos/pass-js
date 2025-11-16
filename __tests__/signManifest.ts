import { expect, test } from 'vitest';

import { randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import * as path from 'path';

import { signManifest } from '../src/lib/signManifest-forge';
import { Template } from '../src/template';

const TEST_STRING = randomBytes(1024).toString('base64');

test('signManifest', async () => {
  // creating template to load certificate and key
  const template = new Template('generic');
  const certPath =
    process.env.APPLE_PASS_CERT_PATH ||
    '__tests__/resources/bin/certificate.pem';
  const certData = readFileSync(path.join(__dirname, '..', certPath), 'utf8');
  template.setCertificate(certData);

  const jsSignedBuffer = await signManifest(
    template.certificate!,
    template.key!,
    TEST_STRING,
  );
  expect(Buffer.isBuffer(jsSignedBuffer)).toBeTruthy();
});

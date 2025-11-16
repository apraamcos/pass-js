import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { createHash, randomBytes } from 'crypto';
import { unlinkSync, mkdtempSync, writeFileSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';

import * as constants from '../src/constants';
import { Template } from '../src/template';

// Clone all the fields in object, except the named field, and return a new
// object.
//
// object - Object to clone
// field  - Except this field
function cloneExcept(object: any, field: string): any {
  const clone: any = {};
  for (const key in object) {
    if (key !== field) clone[key] = object[key];
  }
  return clone;
}

function unzip(zipFile: string, filename: string): Buffer {
  return execFileSync('unzip', ['-p', zipFile, filename], {
    encoding: 'buffer',
  });
}

const template = new Template('coupon', {
  passTypeIdentifier: 'pass.com.example.passbook',
  teamIdentifier: 'MXL',
  labelColor: 'red',
});

const fields = {
  serialNumber: '123456',
  organizationName: 'Acme flowers',
  description: '20% of black roses',
};

describe('Pass', () => {
  beforeAll(async () => {
    const certPath =
      process.env.APPLE_PASS_CERT_PATH ||
      '__tests__/resources/bin/certificate.pem';
    const certData = readFileSync(path.join(__dirname, '..', certPath), 'utf8');
    template.setCertificate(certData);
  });
  it('from template', () => {
    const pass = template.createPass();

    // should copy template fields
    expect(pass.passTypeIdentifier).toBe('pass.com.example.passbook');

    // should start with no images
    expect(pass.images.size).toBe(0);

    // should create a structure based on style
    expect(pass.style).toBe('coupon');
    // labelColor is array of 3 numbers
    expect(pass.labelColor).toBeInstanceOf(Array);
    expect(pass.labelColor).toHaveLength(3);
    // but it stringifies to rgb string and Jest is using stringify for equality
    expect(JSON.stringify(pass.labelColor)).toStrictEqual('"rgb(255, 0, 0)"');
  });

  //
  it('barcodes as Array', () => {
    const pass = template.createPass(cloneExcept(fields, 'serialNumber'));
    expect(() => {
      pass.barcodes = [
        {
          format: 'PKBarcodeFormatQR',
          message: 'Barcode message',
          messageEncoding: 'iso-8859-1',
        },
      ];
    }).not.toThrow();
  });

  it('without serial number should not be valid', () => {
    const pass = template.createPass(cloneExcept(fields, 'serialNumber'));
    expect(() => pass.validate()).toThrow('serialNumber is required in a Pass');
  });

  it('without organization name should not be valid', () => {
    const pass = template.createPass(cloneExcept(fields, 'organizationName'));
    expect(() => pass.validate()).toThrow(
      'organizationName is required in a Pass',
    );
  });

  it('without description should not be valid', () => {
    const pass = template.createPass(cloneExcept(fields, 'description'));
    expect(() => pass.validate()).toThrow('description is required in a Pass');
  });

  it('without icon.png should not be valid', () => {
    const pass = template.createPass(fields);
    expect(() => pass.validate()).toThrow('Missing required image icon.png');
  });

  it('without logo.png should not be valid', async () => {
    const pass = template.createPass(fields);
    await pass.images.add(
      'icon',
      readFileSync(path.resolve(__dirname, './resources/icon.png')),
      undefined,
      'en-US',
    );

    expect.assertions(1);
    try {
      await pass.asBuffer();
    } catch (err) {
      expect(err).toHaveProperty('message', 'Missing required image logo.png');
    }
  });

  it('boarding pass has string-only property in structure fields', async () => {
    const templ = await Template.load(
      path.resolve(__dirname, './resources/passes/BoardingPass.pass/'),
    );
    expect(templ.style).toBe('boardingPass');
    // ensures it parsed color read from JSON
    expect(templ.backgroundColor).toEqual([50, 91, 185]);
    // ensure it parses well fields
    expect(templ.backFields.size).toBe(2);
    expect(templ.auxiliaryFields.size).toBe(4);
    expect(templ.relevantDate).toBeInstanceOf(Date);
    expect((templ.relevantDate as Date).getFullYear()).toBe(2012);
    expect(templ.barcodes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ message: expect.any(String) }),
      ]),
    );
    // switching transit type
    const pass = templ.createPass();
    expect(pass.transitType).toBe(constants.TRANSIT.AIR);
    pass.transitType = constants.TRANSIT.BUS;
    expect(pass.transitType).toBe(constants.TRANSIT.BUS);
    expect(pass.toJSON()).toMatchObject({
      boardingPass: expect.objectContaining({
        transitType: constants.TRANSIT.BUS,
      }),
    });
  });

  it('should convert back to the same pass.json', async () => {
    const t = await Template.load(
      path.resolve(__dirname, './resources/passes/Event.pass'),
    );
    expect(JSON.parse(JSON.stringify(t))).toEqual(
      require('./resources/passes/Event.pass/pass.json'),
    );
  });

  it('asBuffer returns buffer with ZIP file', async () => {
    const pass = template.createPass(fields);
    await pass.images.load(path.resolve(__dirname, './resources'));
    pass.headerFields.add({ key: 'date', value: 'Date', label: 'Nov 1' });
    pass.primaryFields.add({
      key: 'location',
      label: 'Place',
      value: 'High ground',
    });
    const tmd = mkdtempSync(`${tmpdir()}${path.sep}`);
    const passFileName = path.join(
      tmd,
      `pass-${randomBytes(10).toString('hex')}.pkpass`,
    );
    const buf = await pass.asBuffer();
    expect(Buffer.isBuffer(buf)).toBeTruthy();
    writeFileSync(passFileName, buf);
    // test that result is valid ZIP at least
    const stdout = execFileSync('unzip', ['-t', passFileName], {
      encoding: 'utf8',
    });
    unlinkSync(passFileName);
    expect(stdout).toContain('No errors detected in compressed data');
  });
});

describe('generated', () => {
  const tmd = mkdtempSync(`${tmpdir()}${path.sep}`);
  const passFileName = path.join(
    tmd,
    `pass-${randomBytes(10).toString('hex')}.pkpass`,
  );

  beforeAll(async () => {
    const pass = template.createPass(fields);
    await pass.images.load(path.resolve(__dirname, './resources'));
    pass.headerFields.add({ key: 'date', label: 'Date', value: 'Nov 1' });
    pass.primaryFields.add({
      key: 'location',
      label: 'Place',
      value: 'High ground',
    });
    expect(pass.images.size).toBe(8);
    writeFileSync(passFileName, await pass.asBuffer());
  });

  afterAll(async () => {
    unlinkSync(passFileName);
  });

  it('should be a valid ZIP', async () => {
    const stdout = execFileSync('unzip', ['-t', passFileName], {
      encoding: 'utf8',
    });
    expect(stdout).toContain('No errors detected in compressed data');
  });

  it('should contain pass.json', async () => {
    const res = JSON.parse(unzip(passFileName, 'pass.json').toString('utf8'));
    expect(res).toMatchSnapshot();
  });

  it('should contain a manifest', async () => {
    const res = JSON.parse(
      unzip(passFileName, 'manifest.json').toString('utf8'),
    );
    expect(res).toMatchSnapshot();
  });

  // this test depends on MacOS specific signpass, so, run only on MacOS
  // Skip this test when using self-signed certificate for testing
  if (process.platform === 'darwin' && !process.env.APPLE_PASS_CERT_PATH) {
    it('should contain a signature', async () => {
      const stdout = execFileSync(
        path.resolve(__dirname, './resources/bin/signpass'),
        ['-v', passFileName],
        { encoding: 'utf8' },
      );
      expect(stdout).toContain('*** SUCCEEDED ***');
    });
  }

  it('should contain the icon', async () => {
    const buffer = unzip(passFileName, 'icon.png');
    expect(createHash('sha1').update(buffer).digest('hex')).toBe(
      'e0f0bcd503f6117bce6a1a3ff8a68e36d26ae47f',
    );
  });

  it('should contain the logo', async () => {
    const buffer = unzip(passFileName, 'logo.png');
    expect(createHash('sha1').update(buffer).digest('hex')).toBe(
      'abc97e3b2bc3b0e412ca4a853ba5fd90fe063551',
    );
  });
});

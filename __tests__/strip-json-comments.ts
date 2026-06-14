import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { stripJsonComments } from '../dist/lib/strip-json-comments.js';

describe('stripJsonComments', () => {
  it('strips line comments', () => {
    const out = stripJsonComments('{"a": 1} // trailing');
    assert.deepEqual(JSON.parse(out), { a: 1 });
  });

  it('strips block comments', () => {
    const out = stripJsonComments('{/* x */ "a": /* y */ 1}');
    assert.deepEqual(JSON.parse(out), { a: 1 });
  });

  it('leaves comment-like sequences inside strings intact', () => {
    const out = stripJsonComments(
      '{"url": "http://x.test/a//b", "c": "/* z */"}',
    );
    assert.deepEqual(JSON.parse(out), {
      url: 'http://x.test/a//b',
      c: '/* z */',
    });
  });

  it('handles escaped quotes inside strings', () => {
    const out = stripJsonComments(
      '{"a": "she said \\"hi\\" // not a comment"}',
    );
    assert.deepEqual(JSON.parse(out), { a: 'she said "hi" // not a comment' });
  });

  it('preserves newlines so JSON.parse offsets line up', () => {
    const src = '{\n  "a": 1 // note\n}';
    const out = stripJsonComments(src);
    assert.equal(out.length, src.length);
    assert.equal((out.match(/\n/g) ?? []).length, 2);
    assert.deepEqual(JSON.parse(out), { a: 1 });
  });

  it('preserves newlines inside block comments', () => {
    const src = '{"a": 1 /* multi\nline */ }';
    const out = stripJsonComments(src);
    assert.equal((out.match(/\n/g) ?? []).length, 1);
    assert.deepEqual(JSON.parse(out), { a: 1 });
  });

  it('leaves input without comments unchanged', () => {
    const src = '{"a":1,"b":[2,3]}';
    assert.equal(stripJsonComments(src), src);
  });

  it('throws on an unterminated block comment', () => {
    assert.throws(
      () => stripJsonComments('{"a": 1 /* never closed'),
      /Unterminated block comment/,
    );
  });

  it('handles CRLF line comments', () => {
    const out = stripJsonComments('{\r\n  "a": 1 // note\r\n}');
    assert.deepEqual(JSON.parse(out), { a: 1 });
  });
});

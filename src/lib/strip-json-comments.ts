// Minimal JSONC comment stripper.
//
// Removes `//` line comments and `/* ... */` block comments from a JSON
// document while leaving comment-like sequences inside string literals
// untouched. Stripped comment bytes are replaced with whitespace so that
// downstream `JSON.parse` error offsets still line up with the original
// source.
//
// This replaces the former `strip-json-comments` runtime dependency,
// keeping the library free of runtime dependencies. Trailing commas are
// left in place — `JSON.parse` is expected to reject malformed input.

type State = 'code' | 'string' | 'lineComment' | 'blockComment';

export function stripJsonComments(input: string): string {
  let state: State = 'code';
  let out = '';
  let escaped = false;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const next = input[i + 1];

    switch (state) {
      case 'code':
        if (ch === '"') {
          state = 'string';
          out += ch;
        } else if (ch === '/' && next === '/') {
          state = 'lineComment';
          out += '  ';
          i++; // consume the second slash
        } else if (ch === '/' && next === '*') {
          state = 'blockComment';
          out += '  ';
          i++; // consume the star
        } else {
          out += ch;
        }
        break;

      case 'string':
        out += ch;
        if (escaped) {
          escaped = false;
        } else if (ch === '\\') {
          escaped = true;
        } else if (ch === '"') {
          state = 'code';
        }
        break;

      case 'lineComment':
        // Preserve line breaks so error positions are unaffected.
        if (ch === '\n' || ch === '\r') {
          state = 'code';
          out += ch;
        } else {
          out += ' ';
        }
        break;

      case 'blockComment':
        if (ch === '*' && next === '/') {
          state = 'code';
          out += '  ';
          i++; // consume the slash
        } else if (ch === '\n' || ch === '\r') {
          out += ch;
        } else {
          out += ' ';
        }
        break;
    }
  }

  // An unterminated block comment is malformed input; fail loudly rather
  // than silently swallow the rest of the document.
  if (state === 'blockComment') {
    throw new SyntaxError('Unterminated block comment in JSON');
  }

  return out;
}

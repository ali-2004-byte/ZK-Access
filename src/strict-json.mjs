/** Parse bounded JSON while rejecting duplicate keys at every object depth. */
export function parseStrictJson(text, maxBytes) {
  if (typeof text !== 'string' || !text.isWellFormed()) throw new TypeError('Expected well-formed UTF-8 JSON text');
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new RangeError('Invalid JSON size limit');
  if (new TextEncoder().encode(text).length > maxBytes) throw new RangeError('JSON exceeds size limit');

  let offset = 0;
  const skipSpace = () => {
    while (offset < text.length && /[ \t\r\n]/.test(text[offset])) offset++;
  };
  const quotedString = () => {
    if (text[offset] !== '"') throw new SyntaxError('Expected a JSON string');
    const start = offset++;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 34) {
        const value = JSON.parse(text.slice(start, ++offset));
        if (!value.isWellFormed()) throw new SyntaxError('Invalid Unicode in JSON string');
        return value;
      }
      if (code < 32) throw new SyntaxError('Unescaped control character in JSON string');
      offset += code === 92 ? 2 : 1;
    }
    throw new SyntaxError('Unterminated JSON string');
  };
  const value = (depth) => {
    if (depth > 64) throw new RangeError('JSON nesting exceeds limit');
    skipSpace();
    const next = text[offset];
    if (next === '"') return quotedString();
    if (next === '{') {
      offset++;
      const object = Object.create(null);
      skipSpace();
      if (text[offset] === '}') {
        offset++;
        return object;
      }
      while (true) {
        const key = quotedString();
        if (Object.hasOwn(object, key)) throw new SyntaxError(`Duplicate JSON key: ${key}`);
        skipSpace();
        if (text[offset++] !== ':') throw new SyntaxError('Expected colon after JSON key');
        object[key] = value(depth + 1);
        skipSpace();
        const separator = text[offset++];
        if (separator === '}') return object;
        if (separator !== ',') throw new SyntaxError('Expected comma or closing brace');
        skipSpace();
      }
    }
    if (next === '[') {
      offset++;
      const array = [];
      skipSpace();
      if (text[offset] === ']') {
        offset++;
        return array;
      }
      while (true) {
        array.push(value(depth + 1));
        skipSpace();
        const separator = text[offset++];
        if (separator === ']') return array;
        if (separator !== ',') throw new SyntaxError('Expected comma or closing bracket');
      }
    }
    for (const [word, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(word, offset)) {
        offset += word.length;
        return parsed;
      }
    }
    const number = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(offset));
    if (number) {
      offset += number[0].length;
      return JSON.parse(number[0]);
    }
    throw new SyntaxError('Invalid JSON value');
  };

  const parsed = value(0);
  skipSpace();
  if (offset !== text.length) throw new SyntaxError('Unexpected data after JSON value');
  return parsed;
}

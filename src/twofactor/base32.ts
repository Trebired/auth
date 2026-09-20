import { normalizers as normalize } from "@trebired/utils";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(input: Uint8Array) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of input) {
    value = (value<<8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5))&31];
      bits -= 5;
    }
  }
  if (bits > 0) output += ALPHABET[(value<<(5 - bits))&31];
  return output;
}

function base32Decode(input: unknown) {
  const text = normalize.toString(input).toUpperCase().replace(/[^A-Z2-7]/gu, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const character of text) {
    const index = ALPHABET.indexOf(character);
    if (index < 0) continue;
    value = (value<<5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8))&255);
      bits -= 8;
    }
  }
  return Uint8Array.from(bytes);
}

export { base32Decode, base32Encode };

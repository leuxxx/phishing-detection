// obfuscation.js
const OBF_SECRET_PART1 = 'obf';
const OBF_SECRET_PART2 = 'Key2025';
const OBF_SECRET = OBF_SECRET_PART1 + OBF_SECRET_PART2;

function xorDecode(base64Str, secret) {
  const bytes = Uint8Array.from(atob(base64Str), c => c.charCodeAt(0));
  const secretBytes = new TextEncoder().encode(secret);
  const outChars = new Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    outChars[i] = String.fromCharCode(bytes[i] ^ secretBytes[i % secretBytes.length]);
  }
  return outChars.join('');
}

function getDecodedKey(name) {
  const map = {
    GOOGLE: "LiscKjYAc28EcVgVPDk1EFB0XX4OFzYxDQBZSld0KDAXe1IjZEkK",
    VIRUSTOTAL: "DFoFegRBClUCUVgDUnJQTQUGBwNaAVQpB0BUVgUAClVUelwaV1EKDFlTB3gEGgYHVwdbVwJ5AUtXAAJRV1cFLw==",
    FIREBASE_APIKEY: "LiscKjYAcwMCDD8KDDoMCndXUFsdMiQmEi9gYVtSJxItDw0DHwZ3"
  };
  const b64 = map[name];
  if (!b64) return null;
  return xorDecode(b64, OBF_SECRET);
}

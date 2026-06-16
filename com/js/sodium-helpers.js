// web/js/sodium-helpers.js
// ESM crypto helpers — works in BOTH Node and the browser.
// Ported verbatim from poc/poc.mjs (the validated crypto). The server is BLIND:
// it only ever sees ciphertext, sealed keys, and public keys — never plaintext or secrets.
//
// Import note: we import the bare specifier 'libsodium-wrappers'.
//   - In Node it resolves from node_modules (the integration test runs inside server/).
//   - In the browser it is resolved via an <script type="importmap"> entry (see com.html),
//     which for real deployment will be a VENDORED copy served from our own origin with SRI.
import _sodium from 'libsodium-wrappers';

let sodium = null;

// Resolve once libsodium's WASM is initialised. Idempotent — safe to await repeatedly.
export async function ready() {
  if (sodium) return sodium;
  await _sodium.ready;
  sodium = _sodium;
  return sodium;
}

// ── base64 <-> Uint8Array ──────────────────────────────────────────────────
// Use libsodium's own codecs so behaviour is identical in Node and browser.
export function toB64(bytes) {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}
export function fromB64(b64) {
  return sodium.from_base64(b64, sodium.base64_variants.ORIGINAL);
}
export function fromString(str) {
  return sodium.from_string(str);
}
export function toString(bytes) {
  return sodium.to_string(bytes);
}

// ── symmetric wrap key derivation ──────────────────────────────────────────
// wrapKeyFrom(exportKey) = generichash(32, exportKey)  (poc line 65)
export function wrapKeyFrom(exportKey) {
  return sodium.crypto_generichash(32, Uint8Array.from(exportKey));
}

// ── secretbox seal/open (nonce || ciphertext) ──────────────────────────────
// seal(bytes,key) prepends a fresh random nonce to the secretbox ciphertext.
export function seal(bytes, key) {
  const n = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const c = sodium.crypto_secretbox_easy(bytes, n, key);
  const out = new Uint8Array(n.length + c.length);
  out.set(n);
  out.set(c, n.length);
  return out;
}
export function open(blob, key) {
  const N = sodium.crypto_secretbox_NONCEBYTES;
  const n = blob.slice(0, N);
  const c = blob.slice(N);
  return sodium.crypto_secretbox_open_easy(c, n, key);
}

// ── message encrypt/decrypt — returns base64 strings ready for the wire ─────
// encryptMessage(str,key) -> { nonce, ciphertext } (both base64)
export function encryptMessage(str, key) {
  const n = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const c = sodium.crypto_secretbox_easy(sodium.from_string(str), n, key);
  return { nonce: toB64(n), ciphertext: toB64(c) };
}
export function decryptMessage(nonceB64, ctB64, key) {
  const n = fromB64(nonceB64);
  const c = fromB64(ctB64);
  return sodium.to_string(sodium.crypto_secretbox_open_easy(c, n, key));
}

// ── file encrypt/decrypt — seal/open over raw bytes (nonce||ciphertext) ─────
// Returns { nonce(base64), ciphertext(Uint8Array) } so the nonce travels as a
// header/field and the ciphertext as the uploaded blob body.
export function encryptBytes(bytes, key) {
  const n = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  const c = sodium.crypto_secretbox_easy(Uint8Array.from(bytes), n, key);
  return { nonce: toB64(n), ciphertext: c };
}
export function decryptBytes(ciphertext, nonceB64, key) {
  const n = fromB64(nonceB64);
  return sodium.crypto_secretbox_open_easy(Uint8Array.from(ciphertext), n, key);
}

// ── identity keypair + sealed-box group-key onboarding ─────────────────────
export function newIdentityKeypair() {
  return sodium.crypto_box_keypair(); // { publicKey, privateKey, keyType }
}
// publicKey can be re-derived from privateKey (poc onboarding note).
export function publicFromPrivate(privateKey) {
  return sodium.crypto_scalarmult_base(Uint8Array.from(privateKey));
}
// wrapped_private_key = seal(privateKey, wrapKeyFrom(exportKey))
export function wrapPrivateKey(privateKey, exportKey) {
  return seal(Uint8Array.from(privateKey), wrapKeyFrom(exportKey));
}
export function unwrapPrivateKey(wrappedBlob, exportKey) {
  return open(Uint8Array.from(wrappedBlob), wrapKeyFrom(exportKey));
}
// Admin seals a GROUP_KEY to a member using ONLY their public key (anonymous sealed box).
export function sealGroupKeyTo(groupKey, publicKey) {
  return sodium.crypto_box_seal(Uint8Array.from(groupKey), Uint8Array.from(publicKey));
}
// Member opens the sealed GROUP_KEY with their identity keypair.
export function openGroupKey(sealedBlob, publicKey, privateKey) {
  return sodium.crypto_box_seal_open(
    Uint8Array.from(sealedBlob),
    Uint8Array.from(publicKey),
    Uint8Array.from(privateKey),
  );
}

// Fresh random symmetric GROUP_KEY (secretbox keygen).
export function newGroupKey() {
  return sodium.crypto_secretbox_keygen();
}

/* =========================================================
   vault.js — password-based file encryption for static hosting

   Files are encrypted with AES-256-GCM. The key is derived from
   the password with PBKDF2-SHA256 (300,000 iterations) and a
   random per-file salt. Nothing about the password is stored
   anywhere: without it the .enc file on GitHub is just noise.

   File layout:
     [0..4]    magic  "TAOC1"   (5 bytes)
     [5..20]   salt             (16 bytes)
     [21..32]  iv               (12 bytes)
     [33.. ]   AES-GCM ciphertext + 16-byte auth tag
   ========================================================= */

const VAULT_MAGIC = new Uint8Array([84, 65, 79, 67, 49]); // "TAOC1"
const VAULT_ITERATIONS = 300000;

async function vaultDeriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: VAULT_ITERATIONS, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function vaultEncrypt(password, plainBuffer) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await vaultDeriveKey(password, salt);
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plainBuffer)
  );

  const out = new Uint8Array(5 + 16 + 12 + cipher.length);
  out.set(VAULT_MAGIC, 0);
  out.set(salt, 5);
  out.set(iv, 21);
  out.set(cipher, 33);
  return out;
}

async function vaultDecrypt(password, encBuffer) {
  const bytes = new Uint8Array(encBuffer);
  if (bytes.length < 34) throw new Error("File is too small to be a vault file.");
  for (let i = 0; i < 5; i++) {
    if (bytes[i] !== VAULT_MAGIC[i]) throw new Error("Not a vault file.");
  }
  const salt = bytes.slice(5, 21);
  const iv = bytes.slice(21, 33);
  const cipher = bytes.slice(33);
  const key = await vaultDeriveKey(password, salt);
  // Throws OperationError when the password is wrong (GCM tag mismatch).
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
}

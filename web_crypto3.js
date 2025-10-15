
/* =======================
    Large-text safe Web Crypto
    ======================= */
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    // --- Safe base64 conversion ---
    function arrayBufferToBase64(buffer) {
  const chunkSize = 0x8000; // 32KB chunks
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
    return btoa(binary);
}

    function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
    const buffer = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        buffer[i] = binary.charCodeAt(i);
  }
    return buffer;
}

    // --- Key derivation ---
    async function deriveKey(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
    {
        name: "PBKDF2",
    salt: salt,
    iterations: 250000,
    hash: "SHA-256"
    },
    keyMaterial,
    {name: "AES-CTR", length: 256 },
    false,
    ["encrypt", "decrypt"]
    );
}

    // --- Encrypt text (supports large text safely) ---
    async function encryptText(text, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
    const counter = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);

    const CHUNK_SIZE = 1024 * 1024; // 1MB
    const textBytes = encoder.encode(text);
    const encryptedChunks = [];

    for (let i = 0; i < textBytes.length; i += CHUNK_SIZE) {
    const chunk = textBytes.slice(i, i + CHUNK_SIZE);
    const encryptedChunk = await crypto.subtle.encrypt(
    {name: "AES-CTR", counter: counter, length: 64 },
    key,
    chunk
    );
    encryptedChunks.push(new Uint8Array(encryptedChunk));
  }

  // Combine salt + counter + encrypted chunks
  const totalLength = salt.length + counter.length + encryptedChunks.reduce((sum, c) => sum + c.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    combined.set(salt, offset); offset += salt.length;
    combined.set(counter, offset); offset += counter.length;
    for (const chunk of encryptedChunks) {
        combined.set(chunk, offset);
    offset += chunk.length;
  }

    return arrayBufferToBase64(combined);
}

    // --- Decrypt text (supports large text safely) ---
    async function decryptText(encryptedBase64, password) {
  const combined = base64ToArrayBuffer(encryptedBase64);
    const salt = combined.slice(0, 16);
    const counter = combined.slice(16, 32);
    const ciphertext = combined.slice(32);

    const key = await deriveKey(password, salt);

    const CHUNK_SIZE = 1024 * 1024; // 1MB
    const decryptedChunks = [];

    for (let i = 0; i < ciphertext.length; i += CHUNK_SIZE) {
    const chunk = ciphertext.slice(i, i + CHUNK_SIZE);
    const decryptedChunk = await crypto.subtle.decrypt(
    {name: "AES-CTR", counter: counter, length: 64 },
    key,
    chunk
    );
    decryptedChunks.push(new Uint8Array(decryptedChunk));
  }

  // Combine all decrypted chunks
  const totalLength = decryptedChunks.reduce((sum, c) => sum + c.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of decryptedChunks) {
        result.set(chunk, offset);
    offset += chunk.length;
  }

    return decoder.decode(result);
}


// Browser: AES-GCM with PBKDF2 -> 256-bit key
// Usage:
// const encrypted = await encrypt("hello world", "myPassword");
// const decrypted = await decrypt(encrypted, "myPassword");

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function randBytes(length) {
    const b = new Uint8Array(length);
    crypto.getRandomValues(b);
    return b;
}

function bufToBase64(buf) {
    // buf is Uint8Array
    let str = "";
    for (let i = 0; i < buf.length; i++) {
        str += String.fromCharCode(buf[i]);
    }
    return btoa(str);
}

function base64ToBuf(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const u8 = new Uint8Array(len);
    for (let i = 0; i < len; i++) u8[i] = bin.charCodeAt(i);
    return u8;
}

async function deriveKey(password, salt, iterations = 250_000) {
    const passKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations,
            hash: "SHA-256",
        },
        passKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encrypt(plaintext, password) {
    const salt = randBytes(16);          // store with the message
    const iv = randBytes(12);            // AES-GCM standard IV length
    const key = await deriveKey(password, salt);

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        encoder.encode(plaintext)
    );

    // Combine salt + iv + ciphertext into one Uint8Array
    const ctU8 = new Uint8Array(ciphertext);
    const out = new Uint8Array(salt.length + iv.length + ctU8.length);
    out.set(salt, 0);
    out.set(iv, salt.length);
    out.set(ctU8, salt.length + iv.length);

    return bufToBase64(out);
}

async function decrypt(b64Combined, password) {
    const combined = base64ToBuf(b64Combined);
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28); // 12 bytes after the 16-byte salt
    const ct = combined.slice(28);

    const key = await deriveKey(password, salt);
    const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ct
    );

    return decoder.decode(plainBuf);
}

import { Console, Random } from "as-wasi";
import { Auth, Hash, SymmetricKey, Aead } from "./crypto";

let msgStr = "test";
let msg = String.UTF8.encode("test", false);
let adStr = "additional data";
let ad = String.UTF8.encode(adStr, false);
let nonce = new ArrayBuffer(12);
Random.randomFill(nonce);

// --- Hashing

Console.log("\n--- Hashing");
let h = Hash.hash("SHA-256", msg, 32)!;
Console.log("\SHA-256(" + msgStr + "):");
Console.log(Uint8Array.wrap(h).toString());

// Keyed hashing

Console.log("\n--- Keyed hashing");
let key = SymmetricKey.generate("Xoodyak-256")!;
let st = Hash.keyed(key)!;
st.absorb(msg);
h = st.squeeze(16)!;
Console.log("\Xoodyak-256(k, " + msgStr + ", 16):");
Console.log(Uint8Array.wrap(h).toString());

// --- Encryption

Console.log("\n--- Encryption");
key = SymmetricKey.generate("AES-256-GCM")!;
let rawKey = key.export()!;
Console.log("\nGenerated AES key:");
Console.log(Uint8Array.wrap(rawKey).toString());

Console.log("\nNonce:");
Console.log(Uint8Array.wrap(nonce).toString());

let aead = Aead.new(key, nonce, ad)!;
let ciphertext = aead.encrypt(msg)!;
Console.log("\nEncrypt(msg=" + msgStr + ", ad=" + adStr + "):");
Console.log(Uint8Array.wrap(ciphertext).toString());

aead = Aead.new(key, nonce, ad)!;
let decrypted = aead.decrypt(ciphertext)!;
Console.log("\nDecrypt(ct, ad=" + adStr + "):");
Console.log(String.UTF8.decode(decrypted));

// --- Encryption with detached tags

aead = Aead.new(key, nonce, ad)!;
let ciphertextAndTag = aead.encryptDetached(msg)!;
Console.log("\nEncryptDetached(msg=" + msgStr + ", ad=" + adStr + "):");
Console.log("Ciphertext:");
Console.log(Uint8Array.wrap(ciphertextAndTag.ciphertext).toString());
Console.log("Raw tag:");
Console.log(Uint8Array.wrap(ciphertextAndTag.rawTag).toString());

aead = Aead.new(key, nonce, ad)!;
decrypted = aead.decryptDetached(ciphertextAndTag)!;
Console.log("\nDecryptDetached(ct, tag, ad = " + adStr + "): ");
Console.log(String.UTF8.decode(decrypted));

// --- Authentication

Console.log("\n--- Authentication");
key = SymmetricKey.generate("HMAC/SHA-256")!;
let tag = Auth.auth(msg, key)!;
Console.log("\nHMAC/SHA-256(" + msgStr + "):");
Console.log(Uint8Array.wrap(tag).toString());

Console.log("Verifies:")
let verified = Auth.verify(msg, key, tag);
Console.log(verified.toString());


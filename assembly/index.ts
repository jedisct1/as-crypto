import { Console, Random } from "./as-wasi";
import { Hash, SymmetricKey, Aead } from "./crypto";

let msgStr = "test";
let msg = String.UTF8.encode("test", false);
let adStr = "additional data";
let ad = String.UTF8.encode(adStr, false);
let nonce = new ArrayBuffer(12);
Random.randomFill(nonce);

Console.log("\n--- Hashing");
Console.log("\nHash(" + msgStr + ")");
let h = Hash.digest("SHA-256", msg, 32)!;
Console.log(Uint8Array.wrap(h).toString());

Console.log("\n--- Encryption");
let key = SymmetricKey.generate("AES-256-GCM")!;
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



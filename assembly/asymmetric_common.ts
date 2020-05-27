import * as crypto from "./wasi_crypto";
import { error, buf, ptr, fromWasiArray } from "./common";

export class PublicKey {
    handle: crypto.publickey

    constructor(handle: crypto.publickey) {
        this.handle = handle;
    }

    protected as(encoding: crypto.publickey_encoding): ArrayBuffer | null {
        if ((error.last = crypto.publickey_export(this.handle, encoding, buf))) {
            return null;
        }
        return fromWasiArray(load<crypto.symmetric_tag>(buf));
    }

    raw(): ArrayBuffer | null {
        return this.as(crypto.publickey_encoding.RAW);
    }

    der(): ArrayBuffer | null {
        return this.as(crypto.publickey_encoding.DER);
    }

    pem(): ArrayBuffer | null {
        return this.as(crypto.publickey_encoding.PEM);
    }

    sec(): ArrayBuffer | null {
        return this.as(crypto.publickey_encoding.SEC);
    }

    compressedSec(): ArrayBuffer | null {
        return this.as(crypto.publickey_encoding.COMPRESSED_SEC);
    }

    protected static from(alg: string, encoded: ArrayBuffer, encoding: crypto.publickey_encoding): PublicKey | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.publickey_import(wasiAlg.ptr, wasiAlg.length, changetype<ptr<u8>>(encoded), encoded.byteLength, encoding, buf))) {
            return null;
        }
        return new PublicKey(load<crypto.handle>(buf));
    }

    static fromRaw(alg: string, encoded: ArrayBuffer): PublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.RAW);
    }

    static fromDer(alg: string, encoded: ArrayBuffer): PublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.DER);
    }

    static fromPem(alg: string, encoded: ArrayBuffer): PublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.PEM);
    }

    static fromSec(alg: string, encoded: ArrayBuffer): PublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.SEC);
    }

    static fromCompressedSec(alg: string, encoded: ArrayBuffer): PublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.COMPRESSED_SEC);
    }
}

export class KeyPair {
    handle: crypto.keypair;
    alg: string;

    constructor(handle: crypto.keypair, alg: string) {
        this.handle = handle;
        this.alg = alg;
    }

    static generate(alg: string): KeyPair | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.keypair_generate(wasiAlg.ptr, wasiAlg.length, crypto.opt_options.none(), buf))) {
            return null;
        }
        return new KeyPair(load<crypto.keypair>(buf), alg);
    }

    publicKey(): PublicKey | null {
        if ((error.last = crypto.keypair_publickey(this.handle, buf))) {
            return null;
        }
        return new PublicKey(load<crypto.publickey>(buf));
    }

    protected as(encoding: crypto.keypair_encoding): ArrayBuffer | null {
        if ((error.last = crypto.keypair_export(this.handle, encoding, buf))) {
            return null;
        }
        return fromWasiArray(load<crypto.symmetric_tag>(buf));
    }

    raw(): ArrayBuffer | null {
        return this.as(crypto.keypair_encoding.RAW);
    }

    pkcs8(): ArrayBuffer | null {
        return this.as(crypto.keypair_encoding.PKCS8);
    }

    der(): ArrayBuffer | null {
        return this.as(crypto.keypair_encoding.DER);
    }

    pem(): ArrayBuffer | null {
        return this.as(crypto.keypair_encoding.PEM);
    }

    protected static from(alg: string, encoded: ArrayBuffer, encoding: crypto.keypair_encoding): KeyPair | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.keypair_import(wasiAlg.ptr, wasiAlg.length, changetype<ptr<u8>>(encoded), encoded.byteLength, encoding, buf))) {
            return null;
        }
        return new KeyPair(load<crypto.handle>(buf), alg);
    }

    static fromRaw(alg: string, encoded: ArrayBuffer): KeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.RAW);
    }

    static fromPkcs8(alg: string, encoded: ArrayBuffer): KeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.PKCS8);
    }

    static fromPem(alg: string, encoded: ArrayBuffer): KeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.PEM);
    }

    static fromDer(alg: string, encoded: ArrayBuffer): KeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.DER);
    }
}
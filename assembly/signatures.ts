import * as crypto from "./wasi_crypto";
import { error, buf, ptr, fromWasiArray } from "./common";

export class Signature {
    handle: crypto.signature;

    constructor(handle: crypto.signature) {
        this.handle = handle;
    }

    protected as(encoding: crypto.signature_encoding): ArrayBuffer | null {
        if ((error.last = crypto.signature_export(this.handle, encoding, buf))) {
            return null;
        }
        return fromWasiArray(load<crypto.symmetric_tag>(buf));
    }

    raw(): ArrayBuffer | null {
        return this.as(crypto.signature_encoding.RAW);
    }

    der(): ArrayBuffer | null {
        return this.as(crypto.signature_encoding.DER);
    }

    protected static from(alg: string, encoded: ArrayBuffer, encoding: crypto.signature_encoding): Signature | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.signature_import(wasiAlg.ptr, wasiAlg.length, changetype<ptr<u8>>(encoded), encoded.byteLength, encoding, buf))) {
            return null;
        }
        return new Signature(load<crypto.handle>(buf));
    }

    static fromRaw(alg: string, encoded: ArrayBuffer): Signature | null {
        return this.from(alg, encoded, crypto.signature_encoding.RAW);
    }

    static fromDer(alg: string, encoded: ArrayBuffer): Signature | null {
        return this.from(alg, encoded, crypto.signature_encoding.DER);
    }
}

export class SignaturePublicKey {
    handle: crypto.signature_publickey

    constructor(handle: crypto.signature_publickey) {
        this.handle = handle;
    }

    protected as(encoding: crypto.publickey_encoding): ArrayBuffer | null {
        if ((error.last = crypto.signature_publickey_export(this.handle, encoding, buf))) {
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

    protected static from(alg: string, encoded: ArrayBuffer, encoding: crypto.publickey_encoding): SignaturePublicKey | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.signature_publickey_import(wasiAlg.ptr, wasiAlg.length, changetype<ptr<u8>>(encoded), encoded.byteLength, encoding, buf))) {
            return null;
        }
        return new SignaturePublicKey(load<crypto.handle>(buf));
    }

    static fromRaw(alg: string, encoded: ArrayBuffer): SignaturePublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.RAW);
    }

    static fromDer(alg: string, encoded: ArrayBuffer): SignaturePublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.DER);
    }

    static fromPem(alg: string, encoded: ArrayBuffer): SignaturePublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.PEM);
    }

    static fromSec(alg: string, encoded: ArrayBuffer): SignaturePublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.SEC);
    }

    static fromCompressedSec(alg: string, encoded: ArrayBuffer): SignaturePublicKey | null {
        return this.from(alg, encoded, crypto.publickey_encoding.COMPRESSED_SEC);
    }

    verify(msg: ArrayBuffer, signature: Signature): bool {
        if ((error.last = crypto.signature_verification_state_open(this.handle, buf))) {
            return false
        }
        let state = load<crypto.signature_verification_state>(buf);
        if ((error.last = crypto.signature_verification_state_update(state, changetype<ptr<u8>>(msg), msg.byteLength))) {
            return false;
        }
        error.last = crypto.signature_verification_state_verify(state, signature.handle);
        crypto.signature_verification_state_close(state);
        return error.last === 0;
    }
}

export class SignatureKeyPair {
    handle: crypto.signature_keypair;
    alg: string;

    constructor(handle: crypto.signature_keypair, alg: string) {
        this.handle = handle;
        this.alg = alg;
    }

    static generate(alg: string): SignatureKeyPair | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.signature_keypair_generate(wasiAlg.ptr, wasiAlg.length, crypto.opt_options.none(), buf))) {
            return null;
        }
        return new SignatureKeyPair(load<crypto.signature_keypair>(buf), alg);
    }

    publicKey(): SignaturePublicKey | null {
        if ((error.last = crypto.signature_keypair_publickey(this.handle, buf))) {
            return null;
        }
        return new SignaturePublicKey(load<crypto.signature_publickey>(buf));
    }

    sign(msg: ArrayBuffer): Signature | null {
        if ((error.last = crypto.signature_state_open(this.handle, buf))) {
            return null
        }
        let state = load<crypto.signature_state>(buf);
        if ((error.last = crypto.signature_state_update(state, changetype<ptr<u8>>(msg), msg.byteLength))) {
            return null;
        }
        if ((error.last = crypto.signature_state_sign(state, buf))) {
            return null;
        }
        crypto.signature_state_close(state);
        return new Signature(load<crypto.signature>(buf));
    }

    protected as(encoding: crypto.keypair_encoding): ArrayBuffer | null {
        if ((error.last = crypto.signature_keypair_export(this.handle, encoding, buf))) {
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

    protected static from(alg: string, encoded: ArrayBuffer, encoding: crypto.keypair_encoding): SignatureKeyPair | null {
        let wasiAlg = new crypto.WasiString(alg);
        if ((error.last = crypto.signature_keypair_import(wasiAlg.ptr, wasiAlg.length, changetype<ptr<u8>>(encoded), encoded.byteLength, encoding, buf))) {
            return null;
        }
        return new SignatureKeyPair(load<crypto.handle>(buf), alg);
    }

    static fromRaw(alg: string, encoded: ArrayBuffer): SignatureKeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.RAW);
    }

    static fromPkcs8(alg: string, encoded: ArrayBuffer): SignatureKeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.PKCS8);
    }

    static fromPem(alg: string, encoded: ArrayBuffer): SignatureKeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.PEM);
    }

    static fromDer(alg: string, encoded: ArrayBuffer): SignatureKeyPair | null {
        return this.from(alg, encoded, crypto.keypair_encoding.DER);
    }
}
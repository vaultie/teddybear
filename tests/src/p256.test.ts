import {
  DID,
  DIDURL,
  Document,
  PrivateSecp256r1,
  PublicSecp256r1,
  verifyJWS,
} from "@vaultie/teddybear";
import { compactVerify, importJWK, JWK } from "jose";
import { describe, it, expect } from "vitest";

const generateP256 = async (): Promise<{
  privateKey: PrivateSecp256r1;
  publicKey: PublicSecp256r1;
  document: Document;
  vm: DIDURL;
}> => {
  const privateKey = PrivateSecp256r1.generate();
  const document = await Document.resolve(privateKey.toDIDKey());
  const vm = document.verificationMethods().keyAgreement[0]!;
  const publicKey = document.getSecp256r1VerificationMethod(vm);

  return {
    privateKey,
    publicKey,
    document,
    vm,
  };
};

describe("can execute p256 operations", () => {
  it("can extract JWK values", async () => {
    const key = PrivateSecp256r1.generate();

    const pub = key.toPublicJWK().toJSON();
    expect(pub).toHaveProperty("crv", "P-256");
    expect(pub).toHaveProperty("x");
    expect(pub).toHaveProperty("y");
    expect(pub).not.toHaveProperty("d");

    const prv = key.toPrivateJWK().toJSON();
    expect(prv).toHaveProperty("crv", "P-256");
    expect(prv).toHaveProperty("x");
    expect(prv).toHaveProperty("y");
    expect(prv).toHaveProperty("d");
  });

  it("can encrypt and decrypt for a single key", async () => {
    const { privateKey, publicKey, vm } = await generateP256();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = PublicSecp256r1.encryptAES(value, [publicKey]);

    expect(privateKey.decryptAES(vm, encrypted)).toStrictEqual(value);
  });

  it("can encrypt and decrypt for multiple keys", async () => {
    const { publicKey: firstKey } = await generateP256();
    const { publicKey: secondKey } = await generateP256();
    const {
      publicKey: thirdKeyPub,
      privateKey: thirdKeyPriv,
      vm: thirdKeyVM,
    } = await generateP256();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = PublicSecp256r1.encryptAES(value, [
      firstKey,
      secondKey,
      thirdKeyPub,
    ]);

    expect(thirdKeyPriv.decryptAES(thirdKeyVM, encrypted)).toStrictEqual(value);
  });

  it("can add new recipients", async () => {
    const {
      publicKey: firstKeyPub,
      privateKey: firstKeyPriv,
      vm: firstKeyDID,
    } = await generateP256();

    const { publicKey: secondKey } = await generateP256();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = PublicSecp256r1.encryptAES(value, [
      firstKeyPub,
      secondKey,
    ]);

    const {
      publicKey: thirdKeyPub,
      privateKey: thirdKeyPriv,
      vm: thirdKeyDID,
    } = await generateP256();

    const recipient = firstKeyPriv.addAESRecipient(
      firstKeyDID,
      encrypted,
      thirdKeyPub,
    );

    encrypted.recipients.push(recipient);

    expect(thirdKeyPriv.decryptAES(thirdKeyDID, encrypted)).toStrictEqual(
      value,
    );
  });

  it("can re-use the same recipient twice", async () => {
    const { publicKey, privateKey, vm } = await generateP256();

    const value = new TextEncoder().encode("Hello, world");

    const first = PublicSecp256r1.encryptAES(value, [publicKey]);
    const second = PublicSecp256r1.encryptAES(value, [publicKey]);

    const firstDecrypted = privateKey.decryptAES(vm, first);
    const secondDecrypted = privateKey.decryptAES(vm, second);

    expect(firstDecrypted).toStrictEqual(secondDecrypted);
  });

  it("can sign JWS values", async () => {
    const key = PrivateSecp256r1.generate();

    const jws = key.signJWS("testvalue");

    const { payload } = await compactVerify(
      jws,
      await importJWK(key.toPublicJWK().toJSON() as JWK),
    );

    expect(new TextDecoder().decode(payload)).toStrictEqual("testvalue");
  });

  it("can extract JWS payload", () => {
    const key = PrivateSecp256r1.generate();

    const jws = key.signJWS("testvalue");

    const { jwk, payload } = verifyJWS(jws);

    expect(jwk!.toJSON()).toStrictEqual(key.toPublicJWK().toJSON());
    expect(new TextDecoder().decode(payload)).toStrictEqual("testvalue");
  });
});

import { PrivateEd25519, verifyJWS } from "@vaultie/teddybear";
import {
  CompactSign,
  JWK,
  compactVerify,
  exportJWK,
  generateKeyPair,
  importJWK,
} from "jose";
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";

// @ts-expect-error Library without TS definitions
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";

describe("can execute common private key operations", () => {
  it("can generate a new key", async () => await PrivateEd25519.generate());

  it("can extract DID values", async () => {
    const key = await PrivateEd25519.generate();
    const documentDID = key.documentDID();

    expect(documentDID).toMatch(/did:key:z6Mk.*/);
    expect(key.ed25519DID()).toMatch(new RegExp(`${documentDID}#z6Mk.*`));
    expect(key.x25519DID()).toMatch(new RegExp(`${documentDID}#z6LS.*`));
  });

  it("can extract JWK values", async () => {
    const key = await PrivateEd25519.generate();

    const pubEd25519 = key.toEd25519PublicJWK().toJSON();
    expect(pubEd25519).toHaveProperty("crv", "Ed25519");
    expect(pubEd25519).toHaveProperty("x");
    expect(pubEd25519).not.toHaveProperty("d");

    const prvEd25519 = key.toEd25519PrivateJWK().toJSON();
    expect(prvEd25519).toHaveProperty("crv", "Ed25519");
    expect(prvEd25519).toHaveProperty("x");
    expect(prvEd25519).toHaveProperty("d");

    const pubX25519 = key.toX25519PublicJWK().toJSON();
    expect(pubX25519).toHaveProperty("crv", "X25519");
    expect(pubX25519).toHaveProperty("x");
    expect(pubX25519).not.toHaveProperty("d");

    const prvX25519 = key.toX25519PrivateJWK().toJSON();
    expect(prvX25519).toHaveProperty("crv", "X25519");
    expect(prvX25519).toHaveProperty("x");
    expect(prvX25519).toHaveProperty("d");
  });

  it("can sign JWS values", async () => {
    const key = await PrivateEd25519.generate();

    const jws = key.signJWS("testvalue", true);
    const { payload } = await compactVerify(
      jws,
      await importJWK(key.toEd25519PublicJWK().toJSON() as JWK),
    );
    expect(new TextDecoder().decode(payload)).toStrictEqual("testvalue");
  });

  it("can extract JWS payload", async () => {
    const key = await PrivateEd25519.generate();

    const jws = key.signJWS("testvalue", true);

    const { jwk, payload } = verifyJWS(jws);
    expect(jwk.toJSON()).toStrictEqual(key.toEd25519PublicJWK().toJSON());
    expect(new TextDecoder().decode(payload)).toStrictEqual("testvalue");
  });

  it("can sign JWS values without embedded keys", async () => {
    const key = await PrivateEd25519.generate();

    const jws = key.signJWS("testvalue", false);

    const { jwk, payload } = verifyJWS(jws, key.toEd25519PublicJWK());
    expect(jwk).toBeUndefined();
    expect(new TextDecoder().decode(payload)).toStrictEqual("testvalue");
  });

  it("can use valid JWS values from other libraries", async () => {
    const { publicKey, privateKey } = await generateKeyPair("EdDSA");
    const publicKeyJWK = await exportJWK(publicKey);

    const jws = await new CompactSign(new TextEncoder().encode("Hello, world"))
      .setProtectedHeader({ alg: "EdDSA", jwk: publicKeyJWK })
      .sign(privateKey);

    const { jwk, payload } = verifyJWS(jws);
    expect(jwk.toJSON()).toStrictEqual(publicKeyJWK);
    expect(new TextDecoder().decode(payload)).toStrictEqual("Hello, world");
  });

  it("can reject JWS values with invalid embedded JWKs from other libraries", async () => {
    const { privateKey } = await generateKeyPair("EdDSA");
    const { publicKey } = await generateKeyPair("EdDSA");

    const jws = await new CompactSign(new TextEncoder().encode("Hello, world"))
      .setProtectedHeader({ alg: "EdDSA", jwk: await exportJWK(publicKey) })
      .sign(privateKey);

    expect(() => verifyJWS(jws)).toThrow();
  });

  it("can reject invalid JWS values", async () => {
    expect(() => verifyJWS("123")).toThrow();
  });

  it("can restore the private key from seed", async () => {
    const seed = new Uint8Array(randomBytes(32));

    const thirdPartyKey = await Ed25519VerificationKey2020.generate({ seed });
    const thirdPartyDid = `did:key:${thirdPartyKey.fingerprint()}`;

    const key = await PrivateEd25519.fromBytes(seed);
    const did = key.documentDID();

    expect(thirdPartyDid).toStrictEqual(did);
  });
});

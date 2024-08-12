import { Document, encryptAES, encryptChaCha20, PrivateEd25519, PrivateX25519, PublicX25519 } from "@vaultie/teddybear";
import { describe, it, expect } from "vitest";

// @ts-expect-error Library without TS definitions
import { Cipher } from "@digitalbazaar/minimal-cipher";

// @ts-expect-error Library without TS definitions
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";

// @ts-expect-error Library without TS definitions
import { X25519KeyAgreementKey2020 } from "@digitalbazaar/x25519-key-agreement-key-2020";

const generateX25519 = async (): Promise<[PublicX25519, PrivateX25519, object, string]> => {
  const key = PrivateEd25519.generate();
  const document = await Document.resolve(key.toDIDKey());
  const vm = document.verificationMethods().keyAgreement?.[0]!;
  return [document.getX25519VerificationMethod(vm), key.toX25519PrivateKey(), document.toJSON(), vm];
}

describe("can execute x25519 operations", () => {
  it("can extract JWK values", async () => {
    const key = PrivateEd25519.generate().toX25519PrivateKey();

    const pubX25519 = key.toPublicJWK().toJSON();
    expect(pubX25519).toHaveProperty("crv", "X25519");
    expect(pubX25519).toHaveProperty("x");
    expect(pubX25519).not.toHaveProperty("d");

    const prvX25519 = key.toPrivateJWK().toJSON();
    expect(prvX25519).toHaveProperty("crv", "X25519");
    expect(prvX25519).toHaveProperty("x");
    expect(prvX25519).toHaveProperty("d");
  });

  it("can encrypt and decrypt for a single key", async () => {
    const [pub, priv] = await generateX25519();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = encryptAES(
      value,
      [pub]
    );

    expect(priv.decryptAES(encrypted)).toStrictEqual(value);
  });

  it("can encrypt and decrypt for multiple keys", async () => {
    const [firstKey] = await generateX25519();
    const [secondKey] = await generateX25519();
    const [thirdKeyPub, thirdKeyPriv] = await generateX25519();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = encryptAES(value, [
      firstKey,
      secondKey,
      thirdKeyPub,
    ]);

    expect(thirdKeyPriv.decryptAES(encrypted)).toStrictEqual(value);
  });

  it("other libraries can decrypt JWEs", async () => {
    const data = new TextEncoder().encode("Hello, world");

    const keyPair = await Ed25519VerificationKey2020.generate();
    const keyAgreementKey =
      await X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({
        keyPair,
      });

    const did = `did:key:${keyPair.fingerprint()}`;
    keyAgreementKey.controller = did;
    keyAgreementKey.id = `${did}#${keyAgreementKey.fingerprint()}`;

    const document = await Document.resolve(did);
    const vm = document.verificationMethods().keyAgreement?.[0]!;
    const firstKey = document.getX25519VerificationMethod(vm);

    const [secondKey] = await generateX25519();

    const jwe = encryptChaCha20(data, [
      firstKey,
      secondKey,
    ]);

    const cipher = new Cipher();

    const decrypted = new Uint8Array(
      await cipher.decrypt({ jwe, keyAgreementKey }),
    );

    expect(decrypted).toStrictEqual(data);
  });

  it("can decrypt JWEs from other libraries", async () => {
    const data = new TextEncoder().encode("Hello, world");

    const [,,firstKeyDocument,firstKeyDID] = await generateX25519();
    const [,secondKey,secondKeyDocument,secondKeyDID] = await generateX25519();

    const recipients = [
      { header: { kid: firstKeyDID, alg: "ECDH-ES+A256KW" } },
      { header: { kid: secondKeyDID, alg: "ECDH-ES+A256KW" } },
    ];

    const documents: Record<string, object> = {
      [firstKeyDID]: firstKeyDocument.verificationMethod[1],
      [secondKeyDID]: secondKeyDocument.verificationMethod[1],
    };

    const keyResolver = async ({ id }: { id: string }) => documents[id];

    const cipher = new Cipher();

    const jwe = await cipher.encrypt({ data, recipients, keyResolver });

    expect(secondKey.decryptChaCha20(jwe)).toStrictEqual(data);
  });

  // it("can add new recipients", async () => {
  //   const firstKey = await PrivateEd25519.generate();
  //   const secondKey = await PublicEd25519.fromDID(
  //     "did:key:z6MkqWhsS8uVAnUpgKUZhZAHz2ioDFbBaR6eZPM8UkUQcrEg",
  //   );

  //   const value = new TextEncoder().encode("Hello, world");

  //   const encrypted = encryptAES(value, [
  //     firstKey.toX25519PublicJWK(),
  //     secondKey.toX25519PublicJWK(),
  //   ]);

  //   const thirdKey = await PrivateEd25519.generate();

  //   const recipient = firstKey.addAESRecipient(
  //     encrypted,
  //     thirdKey.toX25519PublicJWK(),
  //   );

  //   encrypted.recipients.push(recipient);

  //   expect(thirdKey.decryptAES(encrypted)).toStrictEqual(value);
  // });
});

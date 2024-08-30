import {
  DID,
  Document,
  encryptAES,
  encryptChaCha20,
  PrivateEd25519,
  PrivateX25519,
  PublicX25519,
} from "@vaultie/teddybear";
import { describe, it, expect } from "vitest";

// @ts-expect-error Library without TS definitions
import { Cipher } from "@digitalbazaar/minimal-cipher";

// @ts-expect-error Library without TS definitions
import { Ed25519VerificationKey2020 } from "@digitalbazaar/ed25519-verification-key-2020";

// @ts-expect-error Library without TS definitions
import { X25519KeyAgreementKey2020 } from "@digitalbazaar/x25519-key-agreement-key-2020";

const generateX25519 = async (): Promise<{
  ed25519: PrivateEd25519;
  publicX25519: PublicX25519;
  privateX25519: PrivateX25519;
  document: Document;
  x25519VM: string;
}> => {
  const ed25519 = PrivateEd25519.generate();
  const document = await Document.resolve(ed25519.toDIDKey());
  const x25519VM = document.verificationMethods().keyAgreement[0]!;
  const publicX25519 = document.getX25519VerificationMethod(x25519VM);
  const privateX25519 = ed25519.toX25519PrivateKey();

  return {
    ed25519,
    publicX25519,
    privateX25519,
    document,
    x25519VM,
  };
};

describe("can execute x25519 operations", () => {
  it("can extract did:key-related values", async () => {
    const { ed25519, privateX25519, x25519VM } = await generateX25519();

    expect(x25519VM.toString()).toStrictEqual(
      `${ed25519.toDIDKey()}#${privateX25519.toDIDKeyURLFragment()}`,
    );
  });

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
    const { publicX25519, privateX25519, x25519VM } = await generateX25519();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = encryptAES(value, [publicX25519]);

    expect(privateX25519.decryptAES(x25519VM, encrypted)).toStrictEqual(value);
  });

  it("can encrypt and decrypt for multiple keys", async () => {
    const { publicX25519: firstKey } = await generateX25519();
    const { publicX25519: secondKey } = await generateX25519();
    const {
      publicX25519: thirdKeyPub,
      privateX25519: thirdKeyPriv,
      x25519VM: thirdKeyVM,
    } = await generateX25519();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = encryptAES(value, [firstKey, secondKey, thirdKeyPub]);

    expect(thirdKeyPriv.decryptAES(thirdKeyVM, encrypted)).toStrictEqual(value);
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

    const document = await Document.resolve(new DID(did));
    const vm = document.verificationMethods().keyAgreement[0]!;
    const firstKey = document.getX25519VerificationMethod(vm);

    const { publicX25519: secondKey } = await generateX25519();

    const jwe = encryptChaCha20(data, [firstKey, secondKey]);

    const cipher = new Cipher();

    const decrypted = new Uint8Array(
      await cipher.decrypt({ jwe, keyAgreementKey }),
    );

    expect(decrypted).toStrictEqual(data);
  });

  it("can decrypt JWEs from other libraries", async () => {
    const data = new TextEncoder().encode("Hello, world");

    const { document: firstKeyDocument, x25519VM: firstKeyDID } =
      await generateX25519();

    const {
      privateX25519: secondKey,
      document: secondKeyDocument,
      x25519VM: secondKeyDID,
    } = await generateX25519();

    const recipients = [
      { header: { kid: firstKeyDID.toString(), alg: "ECDH-ES+A256KW" } },
      { header: { kid: secondKeyDID.toString(), alg: "ECDH-ES+A256KW" } },
    ];

    const documents: Record<string, object> = {
      [firstKeyDID.toString()]: firstKeyDocument.toJSON().verificationMethod[1],
      [secondKeyDID.toString()]:
        secondKeyDocument.toJSON().verificationMethod[1],
    };

    const keyResolver = async ({ id }: { id: string }) => documents[id];

    const cipher = new Cipher();

    const jwe = await cipher.encrypt({ data, recipients, keyResolver });

    expect(secondKey.decryptChaCha20(secondKeyDID, jwe)).toStrictEqual(data);
  });

  it("can add new recipients", async () => {
    const {
      publicX25519: firstKeyPub,
      privateX25519: firstKeyPriv,
      x25519VM: firstKeyDID,
    } = await generateX25519();

    const { publicX25519: secondKey } = await generateX25519();

    const value = new TextEncoder().encode("Hello, world");

    const encrypted = encryptAES(value, [firstKeyPub, secondKey]);

    const {
      publicX25519: thirdKeyPub,
      privateX25519: thirdKeyPriv,
      x25519VM: thirdKeyDID,
    } = await generateX25519();

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
});

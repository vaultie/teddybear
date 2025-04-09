import {
  ContextLoader,
  DIDURL,
  PrivateEd25519,
  verifyCredential,
  verifyPresentation,
} from "@vaultie/teddybear";
import { readFile } from "node:fs/promises";
import { TestAPI, describe, expect, it } from "vitest";

const vcTest: TestAPI<{ contextLoader: ContextLoader; key: PrivateEd25519 }> =
  it.extend({
    contextLoader: async ({}, use) => {
      await use(
        new ContextLoader({
          "https://w3c.credential.nexus/identity": (
            await readFile(process.env.IDENTITY_CONTEXT!)
          ).toString("utf-8"),
        }),
      );
    },
    key: async ({}, use) => {
      const key = PrivateEd25519.generate();
      await use(key);
    },
  });

describe("can execute verifiable credentials operations", () => {
  it("can create a default context loader", () => new ContextLoader());

  vcTest("can issue a test credential", ({ contextLoader, key }) =>
    key.issueVC(
      new DIDURL(`${key.toDIDKey()}#${key.toDIDKeyURLFragment()}`),
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3c.credential.nexus/identity",
        ],
        type: ["VerifiableCredential", "Identity"],
        id: "https://example.com/test",
        issuer: key.toDIDKey().toString(),
        validFrom: new Date().toISOString(),
        credentialSubject: {
          type: "Person",
          givenName: "John",
          familyName: "Doe",
          birthDate: "2000-01-01",
          document: {
            type: "Document",
            identifier: {
              type: "Identifier",
              idType: "documentNumber",
              idValue: "123-123-123",
            },
            documentType: "identificationCard",
            issuingCountry: "AA",
            issuingState: "AA",
            issuanceDate: "2020-01-01",
            expirationDate: "2030-01-01",
          },
        },
      },
      contextLoader,
    ),
  );

  vcTest("can sign a test presentation", async ({ contextLoader, key }) => {
    const verifiableCredential = await key.issueVC(
      new DIDURL(`${key.toDIDKey()}#${key.toDIDKeyURLFragment()}`),
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3c.credential.nexus/identity",
        ],
        type: ["VerifiableCredential", "Identity"],
        id: "https://example.com/test",
        issuer: key.toDIDKey().toString(),
        validFrom: new Date().toISOString(),
        credentialSubject: {
          type: "Person",
          givenName: "John",
          familyName: "Doe",
          birthDate: "2000-01-01",
          document: {
            type: "Document",
            identifier: {
              type: "Identifier",
              idType: "documentNumber",
              idValue: "123-123-123",
            },
            documentType: "identificationCard",
            issuingCountry: "AA",
            issuingState: "AA",
            issuanceDate: "2020-01-01",
            expirationDate: "2030-01-01",
          },
        },
      },
      contextLoader,
    );

    const verifiablePresentation = await key.presentVP(
      new DIDURL(`${key.toDIDKey()}#${key.toDIDKeyURLFragment()}`),
      {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiablePresentation"],
        holder: key.toDIDKey().toString(),
        verifiableCredential,
      },
      contextLoader,
      undefined,
      "123456",
    );

    const { challenge: credentialChallenge } = await verifyCredential(
      verifiableCredential,
      contextLoader,
    );

    expect(credentialChallenge).toBeUndefined();

    const { challenge: presentationChallenge } = await verifyPresentation(
      verifiablePresentation,
      contextLoader,
    );

    expect(presentationChallenge).toStrictEqual("123456");

    await key.presentVP(
      new DIDURL("did:web:example.com#test-key"),
      {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiablePresentation"],
        holder: key.toDIDKey().toString(),
        verifiableCredential,
      },
      contextLoader,
      undefined,
      "123456",
      {
        cachedDocuments: {
          "did:web:example.com": {
            "@context": ["https://w3.org/ns/did/v1"],
            id: "did:web:example.com",
            authentication: ["did:web:example.com#test-key"],
            assertionMethod: ["did:web:example.com#test-key"],
            verificationMethod: [
              {
                type: "Ed25519VerificationKey2020",
                id: "did:web:example.com#test-key",
                controller: "did:web:example.com",
                publicKeyMultibase: key.toDIDKeyURLFragment().toString(),
              },
            ],
          },
        },
      },
    );
  });
});

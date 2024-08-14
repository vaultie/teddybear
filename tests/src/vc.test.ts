import { ContextLoader, PrivateEd25519 } from "@vaultie/teddybear";
import { readFile } from "node:fs/promises";
import { TestAPI, describe, it } from "vitest";

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
      `${key.toDIDKey()}#testkey`,
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3c.credential.nexus/identity",
        ],
        type: ["VerifiableCredential", "Identity"],
        id: "https://example.com/test",
        issuer: key.toDIDKey(),
        issuanceDate: new Date().toISOString(),
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
      `${key.toDIDKey()}#testkey`,
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3c.credential.nexus/identity",
        ],
        type: ["VerifiableCredential", "Identity"],
        id: "https://example.com/test",
        issuer: key.toDIDKey(),
        issuanceDate: new Date().toISOString(),
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

    await key.presentVP(
      {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiablePresentation"],
        verifiableCredential,
      },
      contextLoader,
      undefined,
      undefined,
    );
  });
});

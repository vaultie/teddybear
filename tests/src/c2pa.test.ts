import { C2PABuilder, ContextLoader, DIDURL, PrivateEd25519, verifyC2PA } from "@vaultie/teddybear";
import { readFileSync } from "fs";
import { readFile } from "fs/promises";
import { TestAPI, describe, expect, it } from "vitest";

const image = readFileSync(process.env.PLACEHOLDER_IMAGE!);
const pdf = readFileSync(process.env.PLACEHOLDER_PDF!);
const thumbnail = readFileSync(process.env.THUMBNAIL_IMAGE!);
const certificate = readFileSync(process.env.CERTIFICATE!);

const c2paTest: TestAPI<{ key: PrivateEd25519 }> = it.extend({
  key: async ({}, use) => {
    // This key should correspond to the certificate private key
    const keyBytes = Buffer.from(
      "5ff5e2393a44256abe197c82742366ff2f998f6822980e726f8fd16d6bd07eb1",
      "hex",
    );
    const key = PrivateEd25519.fromBytes(new Uint8Array(keyBytes));
    await use(key);
  },
});

describe("can execute C2PA operations", () => {
  c2paTest("can sign an image", async ({ key }) => {
    const { signedPayload } = await new C2PABuilder()
      .setManifestDefinition({
        title: "Test Image",
        assertions: [
          {
            label: "stds.schema-org.CreativeWork",
            data: {
              "@context": "http://schema.org/",
              "@type": "CreativeWork",
              url: "https://example.com",
            },
            kind: "Json",
          },
        ],
      })
      .sign(
        key,
        [new Uint8Array(certificate)],
        new Uint8Array(image),
        "image/jpeg",
      );

    const { manifests, validationErrors } = await verifyC2PA(
      signedPayload,
      "image/jpeg",
    );

    expect(validationErrors).toHaveLength(0);

    expect(manifests).toHaveLength(1);
    expect(manifests[0].assertions).toHaveLength(1);
    expect(manifests[0].assertions[0].data.url).toStrictEqual(
      "https://example.com",
    );
  });

  c2paTest("can sign a PDF file", async ({ key }) => {
    const contextLoader = new ContextLoader({
      "https://w3c.credential.nexus/identity": (
        await readFile(process.env.IDENTITY_CONTEXT!)
      ).toString("utf-8"),
    });

    const credentialKey = PrivateEd25519.generate();
    const vc = await credentialKey.issueVC(
      new DIDURL(`${credentialKey.toDIDKey()}#${credentialKey.toDIDKeyURLFragment()}`),
      {
        "@context": [
          "https://www.w3.org/ns/credentials/v2",
          "https://w3c.credential.nexus/identity",
        ],
        type: ["VerifiableCredential", "Identity"],
        id: "https://example.com/test",
        issuer: key.toDIDKey().toString(),
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          id: "https://example.com",
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
      contextLoader
    )

    const { signedPayload } = await new C2PABuilder()
      .setManifestDefinition({
        title: "Test PDF",
        assertions: [
          {
            label: "stds.schema-org.CreativeWork",
            data: {
              "@context": "http://schema.org/",
              "@type": "CreativeWork",
              url: "https://example.com",
            },
            kind: "Json",
          },
        ],
      })
      .addVerifiableCredential(vc)
      .setThumbnail(new Uint8Array(thumbnail), "image/jpeg")
      .sign(
        key,
        [new Uint8Array(certificate)],
        new Uint8Array(pdf),
        "application/pdf",
      );

    const { manifests, validationErrors } = await verifyC2PA(
      signedPayload,
      "application/pdf",
    );

    expect(validationErrors).toHaveLength(0);

    expect(manifests).toHaveLength(1);
    expect(manifests[0].assertions).toHaveLength(1);
    expect(manifests[0].assertions[0].data.url).toStrictEqual(
      "https://example.com",
    );

    expect(manifests[0].credentials).toHaveLength(1);
  });

  c2paTest("can verify a damaged file", async ({ key }) => {
    const { signedPayload } = await new C2PABuilder()
      .setManifestDefinition({
        title: "Test PDF",
        assertions: [
          {
            label: "stds.schema-org.CreativeWork",
            data: {
              "@context": "http://schema.org/",
              "@type": "CreativeWork",
              url: "https://example.com",
            },
            kind: "Json",
          },
        ],
      })
      .sign(
        key,
        [new Uint8Array(certificate)],
        new Uint8Array(pdf),
        "application/pdf",
      );

    const { validationErrors } = await verifyC2PA(
      signedPayload.fill(123, 500, 600),
      "application/pdf",
    );

    expect(validationErrors).toHaveLength(1);
    expect(validationErrors[0].code).toStrictEqual(
      "assertion.dataHash.mismatch",
    );
  });
});

import { verifyW3C } from "@vaultie/teddybear";
import { describe, expect, it } from "vitest";

describe("can verify signed W3C credentials", () => {
  it("can verify a signed W3C credential", async () => {
    const credential = {
      "@context": [
        "https://www.w3.org/ns/credentials/v2",
        "https://example.com/context",
      ],
      id: "https://example.com/698a3cd2-6021-40b1-895f-9aa69330f11b",
      type: ["VerifiableCredential", "DocumentCredential"],
      proof: {
        type: "DataIntegrityProof",
        created: "2026-01-05T18:20:01.331Z",
        proofValue:
          "z5JHHYNjJowXpDmV4RsXXu7fy8evjnwVQBZTLX36MG7VSeqXJ7TiBhmoEfku9xqhBuiYVuesGNaVYZMgvDFADG1Rd",
        cryptosuite: "ecdsa-rdfc-2019",
        proofPurpose: "assertionMethod",
        verificationMethod:
          "did:key:zDnaeWPwUopbEBBfXFQ9eiV8pUvSmYF7aWMpC67uL1E5mvRD3#zDnaeWPwUopbEBBfXFQ9eiV8pUvSmYF7aWMpC67uL1E5mvRD3",
      },
      issuer: "did:key:zDnaeWPwUopbEBBfXFQ9eiV8pUvSmYF7aWMpC67uL1E5mvRD3",
      validFrom: "2026-01-05T18:20:01Z",
      validUntil: "2027-01-05T18:20:01Z",
      credentialStatus: {
        id: "http://localhost:8000/publishedStatusList/87/8b6cd2bd-9eb2-4052-bab6-5b823ded85c6#104943",
        type: "BitstringStatusListEntry",
        statusPurpose: "revocation",
        statusListIndex: "104943",
        statusListCredential:
          "http://localhost:8000/publishedStatusList/87/8b6cd2bd-9eb2-4052-bab6-5b823ded85c6",
      },
      credentialSubject: {
        id: "https://example.com/documentOutputTestSubject",
        type: "Document",
        documentNumber: "123-123-123",
      },
    };

    const contexts: Record<string, object> = {
      "https://example.com/context": {
        "@context": {
          "@protected": true,
          "@version": 1.1,
          Identity: {
            "@id": "https://example.com/context#Identity",
            "@context": {
              "@protected": true,
              "@version": 1.1,
              firstName: { "@id": "https://example.com/context#firstName" },
              dateOfBirth: { "@id": "https://example.com/context#dateOfBirth" },
              lastName: { "@id": "https://example.com/context#lastName" },
              photo: { "@id": "https://example.com/context#photo" },
            },
          },
          IdentityCredential: {
            "@id": "https://example.com/context#IdentityCredential",
          },
          Document: {
            "@id": "https://example.com/context#Document",
            "@context": {
              "@protected": true,
              "@version": 1.1,
              dateOfIssue: { "@id": "https://example.com/context#dateOfIssue" },
              documentNumber: {
                "@id": "https://example.com/context#documentNumber",
              },
              dateOfExpiry: {
                "@id": "https://example.com/context#dateOfExpiry",
              },
            },
          },
          DocumentCredential: {
            "@id": "https://example.com/context#DocumentCredential",
          },
          Passthrough: {
            "@id": "https://example.com/context#Passthrough",
            "@context": {
              "@protected": true,
              "@version": 1.1,
              passthroughWorks: {
                "@id": "https://example.com/context#passthroughWorks",
              },
            },
          },
          PassthroughTest: {
            "@id": "https://example.com/context#PassthroughTest",
          },
        },
      },
    };

    const statusLists: Record<string, object> = {
      "http://localhost:8000/publishedStatusList/87/8b6cd2bd-9eb2-4052-bab6-5b823ded85c6":
        {
          "@context": ["https://www.w3.org/ns/credentials/v2"],
          type: ["VerifiableCredential", "BitstringStatusListCredential"],
          credentialSubject: {
            type: "BitstringStatusList",
            statusPurpose: "revocation",
            encodedList:
              "uH4sIAAAAAAAA_-3AAQ0AAAjAoEewf1pz6KAAAAAAAAAAAAAAAAC-mgAAAOCKBeqxjHoAQAAA",
          },
        },
    };

    const result = await verifyW3C(credential, {
      trustAnchors: {
        w3c: ["did:key:zDnaeWPwUopbEBBfXFQ9eiV8pUvSmYF7aWMpC67uL1E5mvRD3"],
      },

      statusListFetcher: async (url: string) => {
        return statusLists[url];
      },

      remoteContextFetcher: async (url: string) => {
        return new TextEncoder().encode(JSON.stringify(contexts[url]));
      },

      didWebClient: async () => {},
    });

    expect(result).toMatchObject({
      id: "https://example.com/698a3cd2-6021-40b1-895f-9aa69330f11b",
      issuer: "did:key:zDnaeWPwUopbEBBfXFQ9eiV8pUvSmYF7aWMpC67uL1E5mvRD3",
      types: [
        "https://www.w3.org/2018/credentials#VerifiableCredential",
        "https://example.com/context#DocumentCredential",
      ],
      notAfterTs: 1799173201,
      notBeforeTs: 1767637201,
    });
  });
});

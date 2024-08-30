import { DID, Document } from "@vaultie/teddybear";
import { describe, it, expect } from "vitest";

describe("can execute DID document-related operations", () => {
  it("can resolve did:key", async () => {
    const document = await Document.resolve(
      new DID("did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R"),
    );

    expect(
      document.verificationMethods().assertionMethod[0].toString(),
    ).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R",
    );

    expect(
      document.verificationMethods().authentication[0].toString(),
    ).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R",
    );

    expect(
      document.verificationMethods().keyAgreement[0].toString(),
    ).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6LSej1Ss4cgai4cK8KspVmAEgCa7TP7c6zGHtftB16YNXoE",
    );
  });

  it("can resolve did:web", async () => {
    const document = await Document.resolve(
      new DID("did:web:issuer.localhost"),
      {
        requireHighAssuranceVerification: false,
      },
    );

    expect(
      document.verificationMethods().assertionMethod[0].toString(),
    ).toStrictEqual("did:web:issuer.localhost#key-1");

    expect(
      document.verificationMethods().authentication[0].toString(),
    ).toStrictEqual("did:web:issuer.localhost#key-1");
  });
});

import { Document } from "@vaultie/teddybear";
import { describe, it, expect } from "vitest";

describe("can execute DID document-related operations", () => {
  it('can resolve did:key', async () => {
    const document = await Document.resolve("did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R");

    expect(document.verificationMethods().assertionMethod?.[0]).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R"
    );

    expect(document.verificationMethods().authentication?.[0]).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R"
    );

    expect(document.verificationMethods().keyAgreement?.[0]).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6LSej1Ss4cgai4cK8KspVmAEgCa7TP7c6zGHtftB16YNXoE"
    );
  })
});

import { DID, Document } from "@vaultie/teddybear";
import { describe, it, expect } from "vitest";

describe("can execute DID document-related operations", () => {
  it("can resolve did:key", async () => {
    const ed25519Document = await Document.resolve(
      new DID("did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R"),
    );

    expect(
      ed25519Document.verificationMethods().assertionMethod?.[0].toString(),
    ).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R",
    );

    expect(
      ed25519Document.verificationMethods().authentication?.[0].toString(),
    ).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R",
    );

    expect(
      ed25519Document.verificationMethods().keyAgreement?.[0].toString(),
    ).toStrictEqual(
      "did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R#z6LSej1Ss4cgai4cK8KspVmAEgCa7TP7c6zGHtftB16YNXoE",
    );

    const x25519Document = await Document.resolve(
      new DID("did:key:z6LSej1Ss4cgai4cK8KspVmAEgCa7TP7c6zGHtftB16YNXoE"),
    );

    expect(
      x25519Document.verificationMethods().keyAgreement?.[0].toString(),
    ).toStrictEqual(
      "did:key:z6LSej1Ss4cgai4cK8KspVmAEgCa7TP7c6zGHtftB16YNXoE#z6LSej1Ss4cgai4cK8KspVmAEgCa7TP7c6zGHtftB16YNXoE",
    );

    const p256Document = await Document.resolve(
      new DID("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"),
    );

    expect(
      p256Document.verificationMethods().assertionMethod?.[0].toString(),
    ).toStrictEqual(
      "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    );

    expect(
      p256Document.verificationMethods().authentication?.[0].toString(),
    ).toStrictEqual(
      "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
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
      document.verificationMethods().assertionMethod?.[0].toString(),
    ).toStrictEqual("did:web:issuer.localhost#key-1");

    expect(
      document.verificationMethods().authentication?.[0].toString(),
    ).toStrictEqual("did:web:issuer.localhost#key-1");
  });
});

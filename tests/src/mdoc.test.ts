import {
  DeviceInternalMDoc,
  JWK,
  MDocBuilder,
  PendingMDocPresentation,
  PrivateSecp256r1,
} from "@vaultie/teddybear";
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

const privateDeviceKey = "4vE_IPqGmK28WP7SuCKRvUm-V2XjJcMuO4zqYcNVbTA";
const publicDeviceKey = {
  kty: "EC",
  alg: "ES256",
  crv: "P-256",
  x: "C6ZLoMjEGmBL8CjJHKHRMvb8-9zIfHFFneiyPoIAxcY",
  y: "er7toLYhBpw7I27dgIwtrvBKIcfOp5vwU_ZgP9vm7KQ",
};

const verifierKey = {
  kty: "EC",
  alg: "ES256",
  crv: "P-256",
  x: "Cj6UM4xjOQ3WHRarZh3FntgHp21U6h9KTF_eUL7Q22M",
  y: "aWcMbrHSV7UF1qt20QqYRDaE1E5fzqizsNFoSyO_HOs",
};

const issuerKey = "YZCe2b1Elzo8-MiGr49PY18kpEiPtVj6C09ecg3FOB4";
const certificate = readFileSync(process.env.MDOC_CERTIFICATE!);

describe("can execute mdoc-related operations", () => {
  it("can create and present an mdoc credential", () => {
    const resolvedPrivateDeviceKey = PrivateSecp256r1.fromBytes(
      Buffer.from(privateDeviceKey, "base64url"),
    );

    const resolvedPublicDeviceKey = new JWK(publicDeviceKey)
      .toDynamicVerificationMethod()
      .secp256r1();

    expect(resolvedPublicDeviceKey).toBeDefined();

    const resolvedVerifierKey = new JWK(verifierKey)
      .toDynamicVerificationMethod()
      .secp256r1();

    expect(resolvedVerifierKey).toBeDefined();

    const resolvedIssuerKey = PrivateSecp256r1.fromBytes(
      Buffer.from(issuerKey, "base64url"),
    );

    const mdoc = new MDocBuilder()
      .setDeviceInfo(resolvedPublicDeviceKey!)
      .setDoctype("org.iso.18013.5.1.mDL")
      .setNamespaces({
        "org.iso.18013.5.1": {
          given_name: "John",
          family_name: "Doe",
        },
      })
      .setValidityInfo(new Date(), new Date(), new Date())
      .issue(resolvedIssuerKey, [certificate]);

    expect(mdoc).toBeDefined();

    const deviceInternalMDoc = DeviceInternalMDoc.fromIssuedBytes(mdoc);
    expect(deviceInternalMDoc.docType(), "org.iso.18013.5.1.mDL");

    const extractedNamespaces = deviceInternalMDoc.namespaces();
    expect(extractedNamespaces).toMatchObject({
      "org.iso.18013.5.1": {
        given_name: "John",
        family_name: "Doe",
      },
    });

    const presenter = new PendingMDocPresentation(resolvedVerifierKey, [deviceInternalMDoc]);

    presenter.consent(
      resolvedPrivateDeviceKey,
      {
        "org.iso.18013.5.1.mDL": {
          "org.iso.18013.5.1": {
            given_name: true,
          },
        },
      },
      {
        "org.iso.18013.5.1.mDL": {
          "org.iso.18013.5.1": ["given_name"],
        },
      },
    );
  });
});

import {
  JWK,
  MDocBuilder,
  PrivateSecp256r1,
  StatusListCredential,
} from "@vaultie/teddybear";
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

const deviceKey = {
  kty: "EC",
  alg: "ES256",
  crv: "P-256",
  x: "AFVB5neBhbXug9RuaMOKi8x_3FYr-lmOrdrQXshJjco",
  y: "H9wlcBjJDH1q8Twny8nLTEgcLKPf20Jd7FjraPxv-w8",
};

const issuerKey = "YZCe2b1Elzo8-MiGr49PY18kpEiPtVj6C09ecg3FOB4";
const certificate = readFileSync(process.env.MDOC_CERTIFICATE!);

describe("can execute mdoc-related operations", () => {
  it("can create an mdoc credential", () => {
    const resolvedDeviceKey = new JWK(deviceKey)
      .toDynamicVerificationMethod()
      .secp256r1();

    expect(resolvedDeviceKey).toBeDefined();

    const resolvedIssuerKey = PrivateSecp256r1.fromBytes(
      Buffer.from(issuerKey, "base64url"),
    );

    const mdoc = new MDocBuilder()
      .setDeviceInfo(resolvedDeviceKey!)
      .setDoctype("org.iso.18013.5.1.mDL")
      .setNamespaces({
        "org.iso.18013.5.1": {
          "given_name": "John",
          "family_name": "Doe"
        }
      })
      .setValidityInfo(new Date(), new Date(), new Date())
      .issue(resolvedIssuerKey, [certificate]);

    expect(mdoc).toBeDefined();
  });
});

import { verifyC2PA } from "@vaultie/teddybear";
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

const jpeg = readFileSync(process.env.SIGNED_JPEG!);

describe("can verify signed C2PA assets", () => {
  it("can verify a signed JPEG", async () => {
    const { manifests, validationErrors } = await verifyC2PA(
      new Uint8Array(jpeg),
      "image/jpeg",
    );

    expect(manifests[0].certificateChain()).toBeTypeOf("string");
    expect(validationErrors).toHaveLength(0);
  });
});

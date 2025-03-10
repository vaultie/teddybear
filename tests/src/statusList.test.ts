import { BitstringStatusList } from "@vaultie/teddybear";
import { describe, expect, test } from "vitest";

describe("can operate on status list credential subjects", () => {
  test("can decode a credential subject", async () => {
    const statusList = new BitstringStatusList({
      type: "BitstringStatusList",
      statusPurpose: "revocation",
      encodedList:
        "uH4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA",
    });

    expect(statusList.get(0)).toStrictEqual(0);
  });
});

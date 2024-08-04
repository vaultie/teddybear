import { StatusListCredential } from "@vaultie/teddybear";
import { describe, expect, it } from "vitest";

describe("can execute status list operations", () => {
  it("can create an empty status list and serialize it", () => {
    const statusList = new StatusListCredential();
    const serialized = statusList.toJSON();

    expect(serialized).toHaveProperty("encodedList");
    expect(serialized).toHaveProperty("statusPurpose", "revocation");
  });

  it("can handle non-existent id", () => {
    const statusList = new StatusListCredential();
    expect(statusList.isRevoked(12345)).toBeFalsy();
  });

  it("can revoke a credential", () => {
    const statusList = new StatusListCredential();

    const idx = statusList.allocate();
    expect(statusList.isRevoked(idx)).toBeFalsy();
    statusList.revoke(idx);
    expect(statusList.isRevoked(idx)).toBeTruthy();
  });

  it("can revoke a lot of credentials", () => {
    const statusList = new StatusListCredential();

    const indices = Array.from({ length: 4096 }, () => statusList.allocate());

    for (const idx of indices) {
      statusList.revoke(idx);
    }

    const serialized = statusList.toJSON();

    expect(serialized).toHaveProperty("encodedList");
    expect(serialized).toHaveProperty("statusPurpose", "revocation");
  });
});

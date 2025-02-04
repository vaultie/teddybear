import { SDJWT } from "@vaultie/teddybear";
import { describe, expect, test } from "vitest";

describe("can operate on SD-JWT credentials", () => {
  test("can disclose a credential", async () => {
    const issued = new SDJWT(
      "eyJhbGciOiJFZERTQSJ9.eyJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vand0SXNzdWVyIiwiaWF0IjoxNzM4NjE1NDQ4LjIwOTM2NTQsIl9zZCI6WyJENTdfalZvUENUNlQzR2cxN1YxaENDVzVsaW5wOVN1VlJIYjBCNDJuNVFFIiwiWG1iU3VUYzcyb09sUEVRM0VjblRoNW5fRVJ3YzdRMjdWcmt4TmRLWExHbyIsImtrU1Y0c284RmhOLWpaNmIxNXRxbWg0Wlg1WUNDWG04UmdTYXNWR3JCbDAiLCJkdXF5Umt3Ql85MnYwMmdFMlFKM0hKcFlQd1ZYREk0VXRsMEw1c0pIaXJFIiwiMllfRWR4UjhzR3E1aXo1X0Z2RGhWdHVEZ2pjSHVMenJRRzIzdTlJS2FjRSJdfQ.8END5spcxROVeDtMrZLKa56_b0ksL9meE2LZUXkuluOhfbWnNAQICdUyfnpZLnLItyxowGH5Emq0Wl3uLJVOAw~WyJIYmczVllXc1NGczFVWkhCQnZhc1BRIiwidmN0IiwiaHR0cHM6Ly9leGFtcGxlLmNvbS9jcmVkZW50aWFsL3BpZC8xLjAiXQ~WyJvRWlkZzB1N2RKYXBCWGt1bGs2VEhRIiwic3RhdHVzIix7InN0YXR1c19saXN0Ijp7ImlkeCI6ODYzMDIsInVyaSI6Imh0dHA6Ly8xMjcuMC4wLjE6MTIzMTEvODNmNDgxZWItNjI1OC00NGI3LTk0OGQtNjk4MjgwZDlmZjQ5In19XQ~WyItX3I2LUZ3Zi1oaUhTdVRBcjFMNkZ3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJNTXZNMDh1Y3NWb19EbnNqSTZhdHJBIiwiZmFtaWx5X25hbWUiLCJEb2UiXQ~WyJyTzZaQU9QSzREUWNzUEV5UE1najR3IiwiY25mIix7Imp3ayI6eyJhbGciOiJFUzI1NiIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiQUZWQjVuZUJoYlh1ZzlSdWFNT0tpOHhfM0ZZci1sbU9yZHJRWHNoSmpjbyIsInkiOiJIOXdsY0JqSkRIMXE4VHdueThuTFRFZ2NMS1BmMjBKZDdGanJhUHh2LXc4In19XQ~",
    );

    expect(issued.parseUntrusted()).toMatchObject({
      given_name: "John",
      family_name: "Doe",
      iss: "https://example.com/jwtIssuer",
    });

    const disclosed = issued.disclose(["/given_name"]);

    expect(disclosed.parseUntrusted()).toHaveProperty("given_name");
    expect(disclosed.parseUntrusted()).not.toHaveProperty("family_name");
  });
});

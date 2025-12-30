import { verify } from "@vaultie/teddybear";
import { readFileSync } from "fs";
import { describe, expect, it } from "vitest";

const pdf = readFileSync(process.env.SIGNED_PDF!);

describe("can verify signed C2PA assets", () => {
  it("can verify a signed PDF", async () => {
    const result = await verify("application/pdf", new Uint8Array(pdf), {
      trustAnchors: {
        c2pa: [
          `-----BEGIN CERTIFICATE-----
MIIGoTCCBImgAwIBAgIQDKi2VHuJ5tIGiXXNi5uJ4jANBgkqhkiG9w0BAQsFADBs
MQswCQYDVQQGEwJVUzEjMCEGA1UEChMaQWRvYmUgU3lzdGVtcyBJbmNvcnBvcmF0
ZWQxHTAbBgNVBAsTFEFkb2JlIFRydXN0IFNlcnZpY2VzMRkwFwYDVQQDExBBZG9i
ZSBSb290IENBIEcyMB4XDTE2MTEyOTAwMDAwMFoXDTQxMTEyODIzNTk1OVowdTEL
MAkGA1UEBhMCVVMxIzAhBgNVBAoTGkFkb2JlIFN5c3RlbXMgSW5jb3Jwb3JhdGVk
MR0wGwYDVQQLExRBZG9iZSBUcnVzdCBTZXJ2aWNlczEiMCAGA1UEAxMZQWRvYmUg
UHJvZHVjdCBTZXJ2aWNlcyBHMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
ggIBALcfLr29CbNcSGz+DIOubAHqUXglpIA+iaexsohk2vaJdoH5+R3zlfx4mI2Y
js/k7hxVPg1zWnfOsRKoFXhlTJbyBxnvxB3CgcbxA13ZU1wecyBJH5dP0hp+yer0
1/DDcm30oveXkA1DmfX4wmqvjwRY0uWX3jZs4v8kfjLANIyiqFmq0kQhRRQaVBUF
nwIC8lzssTp10DkLnY8TY+lrtF9CAdd/iB9dVnCnFhFlzOI+I4eoS8tvQndxKFRt
6MXFXpzBfxDIA9rV48eDVG0zQdf4PfjEejcOTIaeZP4N2rTRMQMYbboAvk90g0oU
hCX7NqrookVB7V90YTnCtbNTiYE+bNrPcRsuf7sVaXACGitiogyV1t8cTfJ1z5pN
TUlbv5sbX2qa+E70iW4a1O1AN6oUGPZ+Dp9rGx9V9U8Puy03pPCggOWQ4IThET4i
KfybfPd6qL9WxOayZGoHFYNFqo4fPTYQmgQPFckbd6L5RsginTVdlC925+b3RbE5
O6qpqfZmpM9f0rlV2MSH+i+vvEVzmrV1mj5JrnLixNUzznj+0tTeSU6BQrPNJdg9
hLcaEFxgkePCv3E1Eec1f30PoXSDs6KNJxZ++2PGHXdpO/8fQRO/KZqHjJ8OlV2H
1wrlhII+qe46Wy6MUDKFjAlc5YO9llTYSRZUsOGg/H3Ons3hAgMBAAGjggE0MIIB
MDASBgNVHRMBAf8ECDAGAQH/AgEAMDUGA1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9j
cmwuYWRvYmUuY29tL2Fkb2Jlcm9vdGcyLmNybDAOBgNVHQ8BAf8EBAMCAQYwFAYD
VR0lBA0wCwYJKoZIhvcvAQEHMFcGA1UdIARQME4wTAYJKoZIhvcvAQIDMD8wPQYI
KwYBBQUHAgEWMWh0dHBzOi8vd3d3LmFkb2JlLmNvbS9taXNjL3BraS9wcm9kX3N2
Y2VfY3BzLmh0bWwwJAYDVR0RBB0wG6QZMBcxFTATBgNVBAMTDFNZTUMtNDA5Ni0z
MzAdBgNVHQ4EFgQUVyl6Mk3M/uQ1TsAfJHPOc1Or32owHwYDVR0jBBgwFoAUphzh
bVQkTKiPSHK/bqmM1eTsMdQwDQYJKoZIhvcNAQELBQADggIBAHHO5QeMptwt3Mjg
O2VeAJKBleuVICSvn2k4Xcl88bjapU0AZTslwRhcnr5Zt9wbBjtZgyX6M7si8k9v
uyFcVhb1ucmDFfuUtTXgoTFyGZws1jV57oiEEnZjw/NkxFQpJ3kKRRE+DQ8EsaPP
8pH8Oh8fH4bis9MI4Y5FjF5it3TWVyLmFXG8pxy8iTswPr1lN7B9k9Iz7RaexTd/
RmZ3uGBtGlTJZx4bR4cWl1Qor9kVaEeMNULbyh0Kc3zzm0edwpe+Ii0rRlRSj8Ai
2EUqWEReyer1Uv18VuC87zdm+lRCjnLyZjdy4acRUZd2GM1vncJ8LW7h1uliZZo3
32y5tTMSxRpRveWgs99V/MM6mDbL2/fuQF3L/C5evbS15jtTrbGP98CCzVBKeFS2
UxN8Kpt5/ITJwpWYoismQkuy+BNJgpW8fgUUjB93laOo4L3uNf3ytxUDOEAjSJKR
rOxY4y8vqbQvicslqnH7zkaxVfxjoAeYQ/huYISXCKXooA/5R7AkWLDmubBXakRI
cCFi5klrTcHy2XSd3ZAnO8kaZt4GpeqkX05GKcUzccSsrym5GiQ6MUfb7Vqwt4ja
0HfVb8Qt017bs6B26rpnqoHAKnn1hfburJ0OEPRZF83riQKzbkrzyIYAY1bYIB9M
NL5v5ZgkGIgv2NdhngsX4GJS9927
-----END CERTIFICATE-----`,
        ],
        w3c: [],
      },
    });

    expect(result.c2pa).toMatchObject({
      state: true,
    });
  });
});

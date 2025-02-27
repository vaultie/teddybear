import {
  DeviceInternalMDoc,
  JWK,
  MDocBuilder,
  PendingMDocPresentation,
  PrivateSecp256r1,
  PresentedMDoc,
  DIDURL,
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

    const presenter = new PendingMDocPresentation(resolvedVerifierKey!, [
      deviceInternalMDoc,
    ]);

    const presented = presenter.consent(
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

    const presentedMDoc = new PresentedMDoc(presented);

    const mapped = Object.fromEntries(
      presentedMDoc.documents().map((doc) => [doc.docType(), doc.namespaces()]),
    );

    expect(mapped).toMatchObject({
      "org.iso.18013.5.1.mDL": {
        "org.iso.18013.5.1": {
          given_name: "John"
        }
      }
    });
  });

  it("can read external MDocs", () => {
    const deviceInternalMDoc = DeviceInternalMDoc.fromIssuedBytes(
      Buffer.from(
        "omppc3N1ZXJBdXRohEOhASahGCFZAwQwggMAMIIChqADAgECAhQZrMreC6enYCRXOjzbiQEbiFX7WDAKBggqhkjOPQQDAjBcMR4wHAYDVQQDDBVQSUQgSXNzdWVyIENBIC0gVVQgMDExLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwHhcNMjUwMTE0MTI1NzIzWhcNMjYwNDA5MTI1NzIyWjBTMRUwEwYDVQQDDAxQSUQgRFMgLSAwMDMxLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCVVQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQDLnZnh2hDowJ0C4bVT18UV8q-WGYZua1JVd0XsE3K-S2ZBtyHnyFk58i0fyPb3BxTc4Z_ec0SjUUbyjW86itro4IBLTCCASkwHwYDVR0jBBgwFoAUs2y4kRcc16QaZjGHQuGLwEDMlRswGwYDVR0RBBQwEoIQaXNzdWVyLmV1ZGl3LmRldjAWBgNVHSUBAf8EDDAKBggrgQICAAABAjBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX1VUXzAxLmNybDAdBgNVHQ4EFgQUftAgZBJsuCoNLw92rlS78jJff4gwDgYDVR0PAQH_BAQDAgeAMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwIDaAAwZQIwWHgT5JuiDEUPNqVC3e1VZaRyrHqFwiZRDpRXAt4FY9GgqCnIKfIan7IscNasa-g5AjEA7XnkAf5PcyDXg5zpCdzoe3qj5i4g3zq-g7oaTByiceytwFKPlPAlyo0Hmq1_sjX3WQP32BhZA_KnZnN0YXR1c6FuU3RhdHVzTGlzdEluZm-ia3N0YXR1c19saXN0omNpZHgDY3VyaXhoaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L3Rva2VuX3N0YXR1c19saXN0L0ZDL29yZy5pc28uMTgwMTMuNS4xLm1ETC84ZTcxZjFhYi04YmJkLTRjNmEtOWU4Ny0zNDY2NzQ5ZjdkNDlvaWRlbnRpZmllcl9saXN0omJpZGEzY3VyaXhmaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L2lkZW50aWZpZXJfbGlzdC9GQy9vcmcuaXNvLjE4MDEzLjUuMS5tREwvOGU3MWYxYWItOGJiZC00YzZhLTllODctMzQ2Njc0OWY3ZDQ5Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMZ3ZlcnNpb25jMS4wbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI1LTAyLTE4VDE0OjU2OjEwWml2YWxpZEZyb23AdDIwMjUtMDItMThUMTQ6NTY6MTBaanZhbGlkVW50aWzAdDIwMjUtMDItMjVUMDA6MDA6MDBabHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGsAFgghbARuj8vnE6restmlb6Dp_8OemO1mLQd2FTCF9TmHS0BWCDB7M3Z4wrTnJsQZ7wCG2L6JyOon2_7e4IjFmdNBAZaAwJYIOyno4xnz1tru4vksgJvF1UfikzZFSHA-_o7U2De8mnxA1ggps3oZPT_AdgG7BMJt4kz_zr-sTtVSC1562b_VhXpb7wEWCCOx4VlD9j_zc7FhU_7VtxgxILH_SyxdO5T7MY5Il54cQVYIHdyV3vCqj-g_7MzmbeQs9vC4kI82vB--QfKRZZ2eVecBlggjO6kirp3_Cly8IRa9he5KUdeCa53EYD96XxVnHfJ0B4HWCBasA78jaVaxh8exdJRGAqTN27YnPu5615J0vLq_KvE2QhYILT6iYrWBUB-H78LCuR3gHI6VLZDtQsAWWV6aEh6u6pUCVgg2zZngbU4E39vTyh8eyV8VjAyf5yJUwv5yVXNvllKDIMKWCDozCUvnFrnHOv9HW1TUL4JCqanOEkhfYllAPRKw4bSBAtYIKSQfSANELQIyDE7MTnVqzS_QOk7TB7DUb6oXGh65Aa6bWRldmljZUtleUluZm-haWRldmljZUtleaQBAiABIVggtSe9Pf7uWBSR6lDv5jE9jTS9WxXFkCunf291MdlSOzwiWCAMlFnVyIqEXwm3HL4MdUnOo2WVCWLRc1mrQqWkYwHpqG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1NlhAzgfVQZL6eRXohVNSf9T-IVO_HsENPkknfVyGuIjdLjdfmvSJYHi3s_VNlSamujoo7jMUEUycVnqI9ZMrlNbi32puYW1lU3BhY2VzoXFvcmcuaXNvLjE4MDEzLjUuMYzYGFhkpGZyYW5kb21YIOXVXuz70yNzaMCRqCAnLVb5uhdaQdjuvmPpZij5Hq4faGRpZ2VzdElEAGxlbGVtZW50VmFsdWVkYWFhYXFlbGVtZW50SWRlbnRpZmllcmtmYW1pbHlfbmFtZdgYWSjgpGZyYW5kb21YIFikFYJTLTQbLiGuVdiWG48Yt0BWuBnIIC2xvNT16wctaGRpZ2VzdElEAWxlbGVtZW50VmFsdWVZKIH_2P_gABBKRklGAAEBAgAlACUAAP_hAGJFeGlmAABNTQAqAAAACAAFARIAAwAAAAEAAQAAARoABQAAAAEAAABKARsABQAAAAEAAABSASgAAwAAAAEAAwAAAhMAAwAAAAEAAQAAAAAAAAAAACUAAAABAAAAJQAAAAH_2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD_wAALCAGxAWgBAREA_8QAHgABAAEEAwEBAAAAAAAAAAAAAAECBwgJAwQGCgX_xABJEAABAwMDAwIFAAcEBgYLAAABAAIDBAURBgcSCCExCUETIlFhcRQjMkJSgZEVYnKyGDM4dYLCFkOhsdHwJCUmNDVERoWzw9T_2gAIAQEAAD8A2ov9lI8KURERERERERERERERERERERERERERFS_2_KkeFKIiIiIiIiLhD3f-Tkj8-y_Lv-qLDpW2T3rUt9obVb6ZvOaqrallPCxuP2i95AaOx7kgfdWKvXqGdGlirpLfW7-2F80TsONJFU1cWftJDE9rh-CuoPUn6JH_ALG_FuP_ANruA_8A0L8TV_qk9GGlqJ9RS7nVWoKlrcijtFmq3zP_AA6WNkQ_4nhW7PrQdLTh-r0Zud_O00P_APYvIn1sNrhqKenbszql1hbn4Fd-nwfpT-zT81PjgzuSP9a7wvyar1u9NR1k8dD093WemErhBJLqOON7ox4c5gp3cHfVvJwHs5dip9bfRP6RRik2LvZp3uaKp8t4ia9gPkxhsTg_H3c1XBn9ZDpZiqWwCx7hTMEccj5oLVS_DaXNa4x5fUhxczJY75cFzHFri3Dne-0t6o_RhqeOBs26c9jqZW94LpZ6yIsd_C57Y3Rj8h6yT0XrvSW4thptVaG1Nb75aKsZhq6GdssTv-Jue_2yF6NERERERERERFS_2_KkeFKIiIiIiKMhflXq-27Ttsqr1fLnTW-goIH1NTU1ErYoYYmDL3ve44a1o7kkgDwSVrm3m9ZjSmntQT2PZbQH_SilppXRm63GpfTRVHF2MxRAcy0n9kuLSR5asQN8PU36nN4Kkw2zUzdFWhzeP6BYXmPl93zOzIf5Fqxs1LufuTrKk_s_Vu4epL3SNk-K2C43WepjD_4g2RxGe_leYJJ7E-ETJIwScBASPBKcnHy4_wBVPJ38R_qnJ3f5j389_KB7xjDz28d_Cjk76lXJ2m6g96dkqwz7Wbh3exNdJ8SSmglLoJD9XRODmE_kLYl02esRHM-n0x1LWYU7jxjGorRTlzQS7HKanbn5QO5czP8AhctlulNYae1vYKLVOkL9SXmz3KJk1JXUUzZoJWOz3D2nvjwe4ORj9oEL9_IUoiIiIiIiIqX-35UjwpRERERFGR9V0rjcqK2UctwuFwp6SkgZ8WWaeUMYxn8TnEgNH3PZYg9Qnqg9PGzTZbVpK9M1_qABwFNZalr6WF47AS1IBjAz7MLj9eK0-7w9TO8-92oLre9a6-vUtPc5vim1x10jKKJnPlHG2EO4EN-pGVaXJ8ZKEk-SeyIiIiIiJk_VVNe4nu4nyfP18q-_TN1d7v8ATBqCG4aMvVRUWKSYOrrFVSF1JUsH7eG4-R5x-03BHvlbuOm_q_2c6nbEKzQGo2R3uGNjrhYqwiKtoncW8ssJ_Ws5EAPj5A8gCWuyG30Y4uGc-fCqHhSiIiIiIiKl_t-VI8KUREREUHwrXb-b-bfdO239duDuFdxT01KMU1LG8Gorpj-zFEzySXYB9mgEn5QVpk6xPUH191V0lPpSjtA0rpSlmdK6hgqi99Y49gZ3_K04b-6BjKxGc_PgqOTs55HP1yoRERERERERTzdgjkcHGRnyv29K6s1Loe-0updI3uts11onCSCrpJnRTRn3wQckHvke6z86bPV23I0lX0enuoClGqrGS2N10pImR3Gnb7vcGgMmHc5HyuGOxW17bPdHQm8Wi6HXu22qKW-WSvZyiqad7mlhafmY9jgHRyNP7THtDgexAC9hlv1VSIiIiIiKl_t-VI8KUREREXi91d0tH7NaAvO5WvbwLfZrJTGed7scpHZAZFG0_tSSOLWNZ5JcAMdytCPWT1Y3Xqu3Gj1ZJZHWazW6A0ttoDO6TDeTiZH9-PNwIyGgAYGFjzkjwSiIiIiIiIiIiJk4xlTydgjkcE5Iyr6dLvVpuV0r6x_tvRVcaiy10sf9rWSZxNNWMHkgeWSAZ4vHcZGcre_0_dQm3nUlt7R7h7dXUTwzYjraJ5AqLdUAAuhmZ5a7ByD4c3i5uQ4E3SDmuGQVUiIiIiIqX-35UjwpREREXWkqGR5e6TAb5JBwB-c4wPJJ9lpL9T3q-dvbuI7abRN1dLorSFQ9j5Kd5MNfXDLXy9uzmsBc1pPuXH6LBTkc5yc_VERERERERERERETkfqVefph6ndf9Le4UeuNG1BqKWdohulqlcRDcKfJJDseHAk8XeRk4W-rpz6gdE9S21tBuhoWd0dPUONNXUcpBmt9YwNMkEmOwOHMcD4LXtd4IAuuiIiIiIqX-35UjwpREREWt31Q-t46BtNX07bWXWWHUt0h_9oLhTv4mipHMOadrvIleMcj7M-Xy4cdPZkdknwT5VKIiIiIiIiIiIiIink4eHH-qyl6Curq69LO57JLjNLPorUb46a-UoJ4wHOBVNH8TB5Huwn-ELfpbbnR3agprnbaplTS1kTJ4ZWOBD43gFrhjsQQQf5rvIiIiIipf7flSPClEREXUqqyGgp5ayrnbFBCx0kkj3YDWAEknPbAAJJP0XzV9Qeto9xd8tda4o6x1ZTXe-VlRTT9_1kAlIjePoODW4-ytsiIiIiIiIiIiIiIiKoPd7e3ZbmfSN6mK7cnbev2Q1VWPnu2hYmSWueV4LpbY88Wxn3_VOw3_AAujHgLYaiIiIiKl_t-VI8KURERYheqLude9sOkm_v0_VupavVVdTacM7X4cyGdr3TBvvl0UMjfsJHHyAtCrifHt9FCIiIiIiIiIiIiIiIiyS6DOoSHp06h7Fqy6VXCw3Zhs95c8YbHTTPAEhPsI3BkmB5wV9BlJVxVkEdVTSiSCaNskb2O5NLSMhwPvkEFdpERERFS_2_KkeFKIiItT3rS7uw1l00TslROeXW8SX64DPy8pGmOFuPGQ3n3_AL61cIiIiIiIiIiIiIiIiIpDnDw4j38rf76cm_VBvl00WFrviR3rRscWnLrHJJzfJJDCwx1AJ78ZWFp7-HCRvhqyqRERERUv9vypHhSiIiLRt6v5P-lxMM-NP2__ACuWECIiIiIiIiIiIiIiIiItkXorayqbdu5rrQEtaxtFerDFcWQudj4k9POGAtH1-HNIT9gtwoIPgqURERFS_wBvypHhSiIiLRt6wBP-lzN2_wDp-3_5XLCBEREREREREREREREREWQXQpue3abqn0FqarrxSUFRcW2uulLC8CCqaYSOI75-YDPt5X0QMx4a44IGPx9QQuZERERUv9vypHhSiIiLRt6wBH-lzP5_-AW__K5YQIiIiIiIiIiIiIiIiIi5Keeenmjnp5nxSxOD43scWua4HsQR4I-q-l3p81tTbi7KaI1vS1DpWXixUlQXuGHFxjaH57n5uQOR7EkeyuOiIiIqX-35UjwpRERFo29X_wD2uZv9wUP-VywgRERERERERERERERERFLfK3jekFq06h6R2WN8T2HTGpLhaxzPZzXiOrBA_dH_AKUe31BKzhREREVL_b8qR4UoiIi0b-sB_tcTf7gt_wDlcsH0RERERERERERERERERS3ytrnojalu77dupo-SrLrXTTWu5wU7mjjHUStnjlc0jyXshiBB8fDGP3ltLREREVL_AG_KkeFKIiItG3rA_wC1zP8A7gt_-VywgREREREREREREREREREWevo_7l1mj-pGv0FM6UUetbNNAWkgMbUUx-LHIcjJIaJmDBwPiEkHC3XseXZJ7FvsuREREVL_AG_KkeFKIiItGvq_ODuruob9LDb_APK5YQoiIiIiIiIiIiIiIiIiK-fRaysf1XbWR0MrmVB1JSCJ_bseWPv-6CMHx5yvoxi44yDklciIiIqX-35UjwpRERFo89YCz3Sj6snXKspvh0lw0_QyUj85-K1mWOP2w4O_osGkRERERERERERERERERSzue6zs9H_R1v1F1TVd8rQ_4-mtM1dwpmNAIe58kNOSQR-6JjjBB5YzkZW7aMAZwFyoiIipf7flSPClEREWo_1o9vtSu1hojdZ0L5LC63GwiYBuI6kSSzta7v8AvNc4j2-Qn6BayHeVCIiIiIiIiIiIiIiIiJ48LaJ6INJFLf8Admskb-sio7RE3Pji91ST_P5B_VbY8AeAFKIiIqX-35UjwpRERFYvrM2hfvn016528pY3PuNVbxW20NIaf0ume2eFnI9gHvj4Od5DJHEdwF86lTTS0s0tLUQvilicWPY9uHNc0kEEexGCCPqF1kREREREREREREREREUs7nutz_pE9PustqdttR7l60oJ7c_Xz6E22jlAbKykgbK5szxyy34hmw1pby4ta7w_DdhCIiIipf7flSPClEREVDgT3AXzn9ae3w2w6otw9MDn-jm9TV8BfjlwqHGbIADQR85CsUiIiIiIiIiIiIiIiIiyN6DNhKTqD6jtP6SvVCKmw24Pu93a6LnHJTQ4IjeOTcNkfxYT_ewvoRoqKnt9PHSUlPHDBAwRxRxsDWRsAwGtA7AAewXaREREVL_b8qR4UoiIiLWT6xexOimaFtfUHRUr6fUjbnS2SqfGf1dTC-OZwLx7uBYACO-Oy1GoiIiIiIiIiIiIiIiKW-VuN9HLY5ultrr_AL43u0viu2rax1utssrMEWyDBLozx5j4k5cHZJDhBGR4PLY0iIiIipf7flSPClERERYLesT36R4XMHjVluz9h8Go_wDELSAiIiIiIiIiIiIiIiIueGKSeRkUMZfK9wYxrW5JJOMY9ySQAvph2L0ZQbe7O6K0VbqZlPBZ7JR0rIwHD9mEBx-b5i4kkkn6q4CIiIiKl_t-VI8KURERFiX6oembfqLor13UVjMy2WS3XKkeB_q5W1cMZJ-vKOR7ftyz7LQWiIiIiIiIiIiIiIiIrg7D2F-pt6dDWKKF9Q-sv9BG2Jsvwi4Cdpd83FwGACV9LlHTmnhjiZ3Yxgb4AzhdtERERFB8KUREREVvd99s6LeTZ7WO19dI2NmpbTUULJiM_BlewmKXH9x4jf8AfivmvvtjrtMX-56dvFOIa61VM1FVQkg_DnicWPb9-L2nv7gfdfkoiIiIiIiIiIiIiIiv10MWua69W219NHTPmBv8D38Gl3FjQ5xJ4-wx3X0VhgByQMqtERERFB8KUREREVBYzzjstL3qrdJMe02uhvpo9rm6e1nXPbcKVrTiiuBaHF2T-5KeTh_eDvstfaIiIiIiIiIiIiIiIsyfSl01V37rC0_Xx0cs1NZbfX11TMxhLYB8BzWFxPsXvDfyQt733UoiIiIoPhSiIiIiK2XUHs9YN_NntTbVagiYYb7RPjp5sZNNVt-eGZv95j2scB7hpB8r52d1dqtYbN64umgNdWh9DdLXMY3tP7MrOWGyMJ7OY4dwf6rxSIiIiIiIiIiIiIiLbz6NWxd30zpDU--OobbTQs1UIbbY5CD-kOpYJZDUO7j5Y3yiINwfmMJJ7Budl6IiIiIoPhSiIiIiKktb5wM_VYzda3R3pXqn28qoIqOnota26F81kupZxe17W5-BIR3dG_8AZP0JBHhaFtc6F1Xt1qWu0jrWwVVou9tmdBUU1THwIe0_Njt8wyOxB8ELzaIiIiIiIiIiIiKeJV4Omnp01j1LboUO3mjrc6SD4jJ7tXcuDKGjDh8SRzyHBpxkN-VxLsAcgSvoi0NoyxbfaRs2h9NUUdLa7JSRUVJCxgaGRsa1o7DsDgE_zXpURERERUuVSIiIiIiggYxgLX_6vGxbtcbF0e62n7RHJctD1olr3xRD4r6CUCNziQMkRvEZ79g0vPsFpZ-ihERERERERERERZc9A_RNbOr646tOpdSXKxWjTlNT8aughY8uqZXnDCHjBHBjycdx2-q2-9MPSdth0raTn03oCGrqam4SsnuV0rHh1TWva0huQ0cWsAJIa3ABJKvjxb54j-ilEREREVL_AGUjwpREREREVsupWx1mpOnXdLT9spfj11z0Xe6SniDcl80lDM2MAfXkW4XzUlmMAgZGf549sey4kRERERERERERTgk4xkn6Lfd6Yuzr9pOlLT9RXUboLvrGaXUla2RuC1s3FsLRnvj4EcJ4nw5z_qVlxgKURERERFS_2_KkeFKIiIiIi4Z4myRPjc0EO7EEZzn6r59PUI2Os-wnUxqDS2mQG2a6sjvVFCP_AJdk-eUI9sNcHY-gI-ixoRERERERERERFdLpn21l3Y340PoJlD-lQ3S80zaqN0Rew07Xh8odjw0xtcPtlfSXR0dLRUsVBRxsip4IxHHGwdmtAwAPoMey7aIiIiIiKl3lVIiIiIiIqXgkdlqS9aTbeop9Y6G3VpaJ_wAC4UU9nq5gw4E0bubGkj34PwM9jgrWO5QiIiIiIiIiIpatpPo07DU9TJqjqHvdIHvo53adsoeO7ZCxr6qXB8Hi6JmfvJ7hbXQBjwpRERERERQfClERERERFB8K2m_Wy-kN_trb1tZrGkD6G7UzmQTtaDLRVDW_qp4_4XsfggnscFrsgkH5yNwdDai201nedA6ut_6HeLFWPoqqIjw9pPdv8TT2IJ9iF5pERERERERERfq2GxXHUt6oNO2WjfU3C5VUdHSwMbh0sr3BrW_kucB9B3K-jzpj2ct-wuxmj9rqQMM1mtzG1szWFvxqyT9bUSYPs6R7j9hgfuq63gKUREREREUHwpRERERERFQ9ox_2rQr6qNFRUXWVql1DDHG6qo6Geo4ADlJ8EDk7Hk8Wt7lYiIiIiIiIiIiLPD0jtj5Nw9-6ncm40bJLLoSm-N-s7tfWztcyFv8AINe__hH1W7RjWhoAaBnJ8fXyuREREREREUHwpRERERERFS_9lfP_AOppVS1HWdr1sh_1D6SJmf4RTRrFlEREREREREUt8rdV6OW3FfpXpyu-urjGI261vbpqIEd30tKPgfE-2ZRMAP7gPus_B4ClEREREREUHwpRERERERFS5aAPU0pJqTrO14-dpH6Q-llZn-E07AP8qxYRERERERERFLM57Y_mvoI9N7Wdh1h0e6BZYaX9FbZaR9pqojjP6VC_9Y_A9nOcX9-55Z91k8PClEREREREUHwpRERERERFB8LRX6t1pltvWBcql0biy4WSgqGuLcAnDm4B98cRn8rCxEREREREREUtbyOFvA9IXRl40v0oS365Na2LVepKy6UTQXZEDWRU4LgW9iZKeQ9sgjifcrOYeFKIiIiIiIoPhSiIiIiIiKHcvYArW56wPTvcNY6Gs-_mmqQzz6SaaK8sY3LhQSOzHP2OMMeQHEDPF4PgFafH9j2UIiIiIiIiIAT4C9ltVtzfN2dwrDtzpmEvuOoKyOkhIDXBjXH5pDktADQHOOXN7Nx7r6StstB2fa_b3T23en4-Fu03bae2U4PLJjhYG5cXdyTgnP3K9YiIiIiIiIqT2b3VSIiIiIiIi_I1BZbVqWz12nr5QRVtuucEtJV08zMxyxSMLZGOB8ZaSP5r56usnpqufTLvZd9E_otQ7T9U81un6uRpP6RRvcS1vI9nPj7scPfAPurCEYKhEREREREXKxpJw0dzjH1OfAAHutunpQdHddo20x9TGv6SSnut7gfDp-3T07mPgpHkcqt_JvIOkAIZjA4HllweA3ZWyPiPDcj3wuRERERERERQ7wpREREREREXG6MF2QG_0--VYrq36WtI9VO21Vo-9yMor1RtfNZbq2Pm-iqi0gcmju6M_LybnJABb3AWgrdraHXOy2u7lt1uBZXUF4tshY5o-aOZmMtlheO0kbh8wcO2D3DSC1vhUREREREVbW8jjAzn3Hk_TAWxj04PT6duZVRb272WWpg0xQTsdZbRVUz4zdpAA4VDmva3lTDkA0jIe7kAQGnO4ampKelhZBTxMjjjAaxjGgNaBjAAHjwP6LmXDPN8GMyPBDR2PfwPquYEEZClERERERFS5VIiIiIiIiKMBUGOPOcfyWMfW90bad6r9vpoaA0Nu1xaY3PsV1ma7g57Tl1NMWZd8N-HDIDixzg7i7iWu0Pa10FqbbjU9z0Xrux1VmvdnlNPVUVRGQ5rmkZIcMhw75Dhljm4c0kFufMIiIiIi7DIHSubHEwufIQ1gaMknOPHnJ9gFso9P701LlqWvpt4-onTk9BZqeXlZ9OVsJjmr3NdgzVEbsOjjyCAx7Q54HLHEsJ2409JTUsMdNSwsjiiY1kcbWgNY0eAAOwA7YC50XVuEQno5o_HJq54_wBkfhVoiIiIiIoPhB4UoiIiIiIiIqTG05yM57FYldcvQ7pvqq0pLebIKW2a_s8P_qq5v-WOraCXfotQ5oJLCOzXEEsJDvmHJp0Za10LqjbrU9x0VrbT1VZ75bJnU9VR1TC2SJwOcg-HDHcOHyOb8zSQQV5tERERe22x2j3D3j1TT6L2x0hW3-8VX7ENOwNY3scufI8hkbcA5c5wAI7Fbhejj0xtB7Ffomud15rfrLWrXR1EIbCTQWqQNbhsTXd5Xh5d-sc0eBhrMHlnU2JjPDf_AD_5AVaIunc6htJQzVLmkhjc4VdHUsqqaOoizxcMrsoiIiIiIoPhB4UoiIiIiIiIipMbCckd1jN1cdEO2PVbZ5Km7Qssms6SnMFsvtM08m5Ic1k7B2mjyD28tDnEOBWkffvpw3S6bdYy6M3MsLKeUjNLX0xdLRVzPIfDKQCRnIwQ1wx8zRlWqREX72ltE6s1xcorJozS9zvlwmPGOlt1JJUSv8_usBPt9FsP6cPR61he6yi1P1FXmms1pdHHKLBbZXSVsvNuSyeUN4QcCQCGmQuIcA5oAc7Z_tVs3tnsnp1mltsNG2-wULccm00IEkxyTykeRzkIye7ifJXujGwnJHtj-SqREX517jdJbZmNJy5vHCmzROht0URH7Hyj7hfoIiIiIiIoPhB4UoiIiIiIiIiLjcxn8LSQc4I985_714rdHajQO82k6jRe4unqS82mpIIimGeDwctkY7GWuHthap9_fR73XsN9qbjsBW2_VFkkHOC3V1bHS1sI_h5yERyfnk0qwd99NrrW09Rtra_Yi4SsLuIZQ3KhrZMfXhBM53_YvQaO9LLrJ1TLQiv26t2naWtPeqvF4p2fo7fq-KJ0k2f7ojLvssv9qfRf26stRFcd4NyblqQNMZdQWmm_QYP9W7m10jnPkeOZBa5vA4ABHcrP_QW1u3G19A6g0Douz2GGQfrTR0bIXSnv3e4AF3k-fqvWgDzgZUlrSMFox4xhSiIi61UGuAjJzyOVzsjbG0MaMAdgqkREREREVL_ZVIiIiIiIiIijI-qp5AeSfOO_bJ-iwx6s_Ut2v6brvNoWyWio1drSklaytt8T3U0FCxzeQdJMWODnYxhjWknOSWjAdgRbfU76o9Z7m26WvulIbLcrjDTusdBSRsjLXvaxzI3SEHkeY4_EeBnGXAZWaWifUNq31xo9TaLvtuo_02Ogp6y9UBoo6ydxIaYuThL83HI5MaPma08XEhZU7eb9aB3DqI7Zba51LXyMy2kqBxcfs0-Hn8Lz2_fVLoXpwbT1-6FuutDZKwiKG6QU754nTOyRHxY1zgcN9xheT2n9Qjpa3gusVk0_uJBQXOaRsENPdY3UbppH8uLY_ihpcTjvgEDsrs613t2v23u1vs2vda23T1TeJGwUDrjI2GOpld-y1jiQ0n7Zz917qOZsjGmN_LIB-U9iD4Pv2_BXOiIipJOcex8_ZdaPlLOXEYa0cWrtDwpRERERERQfClERERERERFQ57RnJxxXSmutFHUtof0mJ1W9hkZTiUCRzAQC4DOSBnzhRV0EdeI3ySTM-E_mwMkLSHfU48_4fCs11D9HWyfUvRRt3D0zGLrTDlT3WhxBWM-XHF0jRmRn91wx9lh9XdCmkNitT22vpbOwU0McjIqx4FQysdyDo3vMgJZIzJGW4yD25D5l6abRhke5zKN8sbjkD3wTkHP57rvWbRd0tNc25WuV9PMyVronRuGWnl5z_D9_KyDI0T1C6Br9p94rTRVgrITTuEj2D4ry0tEsDiOTJRyyDxBH0WnnrW6KtVdJ2rW1Ecj7tou81E_9j3BrCHRAPcRTzjJw8R8Pmzh3dw4_srLPoi3_ANuurLaeXo_6l4qe4XCCmENirZnPdPUQsjBBExDgyojwC0l3KQnBHY57eyvUpuP0G7yy9K3VNf3XbRj3ifT2qHyPk_RqWUuEUrieUnwHFpaYyMwua48nMGTs3tt0o7rRwXG210VZTVTGywTU7w-OSNwBa5rgSHAjvkdsA-Cv0URFxvBLXAHyqmMDW8cBVIiIiIiIig-FKIiIiIiIijPfCxp61OsPTnSdt1FeJaNt21VfHPprFbCSI3yAAumneOzYowWkgEOc4hrcDk5umKDq-32dvpbOoS764rrlqW1VLXxtlkLKd9L8Tm-jMbCA2B-CwsHgEYPJoK3t9P8A1A6H6itAW3Xmh7g2RlSz9dSuIE1LLgB8TxyPFzCcOzn2I5BzXG64I9h9-66dxtdBdaOS33GliqIJW8XxyDILf_FWi1Ls_TWRjrhZ2yT0UbSXQeXMjBz_ADGPfyrU3mtp6SSVsDSREM9ge32wfdeCr9U3Kkr_AIlDP8CXGGTgfPGPsHef5q8mi9eaL340tVbKbtW2murblSPilbOzlHUtBwDy_dkz3BHdah-sPpr1D0c730tFY7nVf2ZM9t501dgR8WMRyZaOQOTJG7gORDf3T7lXV3435_02elu13u82F8m6O2tdHDcX0FOJP7St0zDzqg1gMkbAY8vBAYHYdn5g1vP6bvWteNi9c0Wy-4d4nfoC-1Jgpo52GQ2mtlfgPZkh0cT3uy8YIBPLDfncd10czKhrZIpQ9hAIc12cg9_bt3HcELsIig-FKIiIiIiIig-FKIiIiIiIoPhed1FqOagcKC10z6itl7AAfLEP4iff8LHPcHo40Pu3qGr1NuhYBf7lXxRRF9dI4_CbGHACIcgGAF7nOAxyJBPhYQbh-k5cbTqKtGndcT01vlYTRR1VJ8V8Tg9vYvDm82hhI7N5AjkewOf0-hap15snqbU-0WoY6-3XrT1S2rdGXsfR1LJj8OOSI4Dy1wYP7vbDg1wcBtB273Kota0LRUsFLcA4sdFyBDy3yW59l7gH28H-qpfGHggtaQfII8qwe9-3U9vgqNVWNpdA8OdUQDPIPJyHf17LDjcLXNo0Pbai-X25RUUETTITNhr3MA88Sc5PjiOTif2QViZrXrZvZq4qvbKmrLVXUtRFURVs7mte0sLuTHR5dkYLSCHNIwc5V99_N4rX11dEh17NRxUW4O01wgnvVKMtbNSzfqTLDjPMO-Q8SQQ5rh4xyuV6cnQzrXRWnZd2tx3PtdTqukYyls7xiaGl58myTN8tkccOEfkNwHAOJDctte9FuxW4tpqKfUehbRWXCoe2WSufTNZM57AAxxez9YRgAEcvb7Lj2RvGq9rr1DsXrc1lfb6Oja7Tl-nEjuVPGWxmkqJXDBlaCC13LLmkgjk0l2Qod4PsfuqkRERERERERFS5SPClERERERFQ9pewtDiPuCuCnt9LS_NFEA89-Tu5_quxxXQulpgukJjmABHZjgO4WI_U9s5RaW1pp_eqz0MzpHB9ju36HTue-QTkNgllAcPkY8FueLsc8_KxriGj7lVfpEMtG7hJHgRCF3AjPnuVkfoHXP8AbtGylub2Nq2sy94cMH7HHgr24P17Z8YK61dR01dTS0VZEySGccZGOHkHx_PPf8rSR6oG3VTtxuFabQ-1zyU0jZ56K6OJc2SAlpMR9uYdkkePOFg85z8kcndse_08LZT6PO0mpbnqzWG41fa4naSfbxY5jI7mKiclknAMAP7I4lxOMZAA88dukVPDHC2KFoDAzi1uO2PphcpjaQQBjP0Xn9W6UodUW11NO34c0fzwTDzFJ9Quroy7XBsb9O6hwLnQDBcBgTxfuvH1OPP3Xqcuz4VaIiIiIiIiIqX-ykeFKIiIiIiIowFKjB-q_F1Tpyg1VYK_Tte0GG4ROjecZwS3Ad-QQCD9lifbrFcNCX6aw3aAiSnkLAXZ5Oa397HjiRhwPnyF-9qaup6CxPqnVGJYeUjAMsw4eMEfVfvdP_U3Z9eVI0peLpTSXJz5GUlS1-WzvY4sfEewAc144YzkvBb5Xf3639o9vIa61zVsVBVUbTUullk4sZEGk_F5nthuC4k4A4EEj5s4idZd6i6rOi-47j2u3yQah23vRpb5Stge7lHE4sMzcgH4To3tmDgXNDXHBOOSwL6TelXW3VVuLHpXT0bqOzUXGa93ZzMspIT34tz2dK7uGj8uPYBfQDtxtvo7anRls0JoeywWyz2iAQU8MbePYeSXHu5xOXF3kkk-69bgeMKVSQPOB28L8y42aKqqYrlEfh1UHdkn1H8J-32XdglfI39YOLx-03-H-fuuwiIiIiIiIiKl_t-VI8KURERERERERRxbnOO6sLvRf7Hb90dCaJfa6uqvGt5ammpnwU4eynZTM-I-aY8mlsYB7HvknC8f1GaedoLbmu1RqCZ0VnoonVFU-jD3upg1vJxIDcubxBAx3ytKeuN0nO3VqtebXVNfYWsc51NKHuZOXO5vke5pc4NLnvccD5WnBAWyWC-2frh6YdK7l3q3Q3TVWkJYaHUVHxLvjTwkBlRw-X5TyD_3mAPcCT3VxOmDp2tNJofc7ZtoqqbTmrbf8F1O1vGOmMjPhu4Edy7JLy92Xd2g8W8QMmOnzp7246b9Dx6I27tZggcRNVVMmXS1U3FrXPc_3J45AHbuVdQMY3HFgGOwwPCqRFTx-6nA84ClEREREREREVL_AG_KkeFKIiIiIiIiKMhcTnsjY6R7-LW5LiT2AHk5PssZti9Y6b373915upa462ah0G52jaCeeN7YJJQ8vqpYebRktcxjC734g-45fodVW59ssmlDpkumlmr3mJrIY3SjIa5xLiB8rPlLebvly7GeXZaCdY2qjsuqbxa6SR72UNyqqUhsXFjWslLWEHk7PINz9vbKut0vdVOsOmC_Xevs1G27Wq9W6Smq7VM8sp5pcARSP-UnMZBHb6n6Bb7Nj5bDddrNM6m068y0OorbS3mGV7HML21EQlaQHAHGHdgW-6uCGMHhoHj2-iqRERERERERERERFB8KURERERERERdczFs4g-G_Lm8uWOwP0XBc7bS3egqLZXxl0FTG-OQNcWngfPcLw9PpDTO02jxYNs9FC300zzyjtlI9zzLxwJZXYL5HEgB0khLjnJKw76prLvUNC3S7aK241Tf7uzIpaWmslTUv5Pc1vIMYwl4bkkgDuAtZMXSX1ZXu5_Dd07bnvqquRz3TVemK6NrnOBLi-WSIAE98lzhkn6rLOxentrXQvTG6XUWgrtcNx9y7ta7ZBDRW2ardpigdO0yy1Xw2ngBgOeOwAABccFbZtAaesukNH2fSGnKCSitWnqOG0UUL2lpbBTMELAM_MQAwAOPd3leoREREREREREREREUHwpRERERERERFQPA_Klvj-Z_711p__eWf4ZP8oVUvl_8AjP8A-NT_ANZ_xf8AMqWeG_lv_IuX_rD_AI_-VcqIiIiIiIiIiIiIi__ZcWVsZW1lbnRJZGVudGlmaWVyaHBvcnRyYWl02BhYbKRmcmFuZG9tWCCxyFsHyH_SyXKTXM3NndFMm6-UkKoe0_eMt_6fwtgtemhkaWdlc3RJRAJsZWxlbWVudFZhbHVl2QPsajIwMDAtMDEtMDFxZWxlbWVudElkZW50aWZpZXJqYmlydGhfZGF0ZdgYWGmkZnJhbmRvbVgg4kc1fgLDLf-LDQp_-d5ZIJasGoUeEyKiryovH35s03RoZGlnZXN0SUQDbGVsZW1lbnRWYWx1ZWUxMTExMXFlbGVtZW50SWRlbnRpZmllcm9kb2N1bWVudF9udW1iZXLYGFhspGZyYW5kb21YINujiw5VWqUG1OG2UYWIaSmuJIVXZyu1DvWgr2kyoBzyaGRpZ2VzdElEBGxlbGVtZW50VmFsdWXZA-xqMjAyNS0wMi0xOHFlbGVtZW50SWRlbnRpZmllcmppc3N1ZV9kYXRl2BhYbaRmcmFuZG9tWCBdyN0NznitrbpIQdwl34vCsrqxV3TuSisbHI_5GIF3bGhkaWdlc3RJRAVsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVydnVuX2Rpc3Rpbmd1aXNoaW5nX3NpZ27YGFh1pGZyYW5kb21YIJdzXyGxYGJCuyjszI8upxNI8zSMw9aC8YxMRiPGmSU_aGRpZ2VzdElEBmxlbGVtZW50VmFsdWVvVGVzdCBNREwgaXNzdWVycWVsZW1lbnRJZGVudGlmaWVycWlzc3VpbmdfYXV0aG9yaXR52BhYtKRmcmFuZG9tWCCUao-3GCu3Ywh14qoj3L2wG8RkPu5ot0vdxI-4Ck7E2mhkaWdlc3RJRAdsZWxlbWVudFZhbHVlgaNqaXNzdWVfZGF0ZdkD7GoyMDAwLTAxLTAxa2V4cGlyeV9kYXRl2QPsajIwMDAtMDEtMDF1dmVoaWNsZV9jYXRlZ29yeV9jb2RlYkFNcWVsZW1lbnRJZGVudGlmaWVycmRyaXZpbmdfcHJpdmlsZWdlc9gYWG2kZnJhbmRvbVggX_WGE9LBXHYxyBOWXpdhw2rjQbRTW7mmXPGYgryh0ztoZGlnZXN0SUQIbGVsZW1lbnRWYWx1ZdkD7GoyMDI1LTAyLTI1cWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRl2BhYZqRmcmFuZG9tWCDgPw1NhKt_tV5G0nR4COqJ1yUv7RdtHkBhN9k4vbaY8WhkaWdlc3RJRAlsZWxlbWVudFZhbHVlYkZDcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyedgYWGCkZnJhbmRvbVggdnDSRikqZ2Yv-YydRMJPvo4_CuRzs9BKOQrfYJDUDRZoZGlnZXN0SUQKbGVsZW1lbnRWYWx1ZfVxZWxlbWVudElkZW50aWZpZXJrYWdlX292ZXJfMTjYGFhjpGZyYW5kb21YIFksxzb65g4wORNjYY2OhcPpFBbf5sUDL4gH0NTVQRUVaGRpZ2VzdElEC2xlbGVtZW50VmFsdWVkYWFhYXFlbGVtZW50SWRlbnRpZmllcmpnaXZlbl9uYW1l",
        "base64url",
      ),
    );

    expect(deviceInternalMDoc.docType()).toStrictEqual("org.iso.18013.5.1.mDL");

    expect(deviceInternalMDoc.namespaces()).toMatchObject({
      "org.iso.18013.5.1": {
        age_over_18: true,
        birth_date: "2000-01-01",
        driving_privileges: [
          { issue_date: "2000-01-01", vehicle_category_code: "AM" },
        ],
      },
    });

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

    const presenter = new PendingMDocPresentation(resolvedVerifierKey!, [
      deviceInternalMDoc,
    ]);

    presenter.consent(
      resolvedPrivateDeviceKey,
      {
        "org.iso.18013.5.1.mDL": {
          "org.iso.18013.5.1": {
            birth_date: true,
          },
        },
      },
      {
        "org.iso.18013.5.1.mDL": {
          "org.iso.18013.5.1": ["birth_date"],
        },
      },
    );
  });
});

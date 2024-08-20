/* tslint:disable */
/* eslint-disable */
/**
 * Teddybear is a JS/TS suite of useful cryptographic utilities shipped
 * as a single ESM/CJS-compatible package.
 *
 * Out-of-the-box, Teddybear supports Ed25519 and X25519 key operations
 * (JWS signing/verification, JWE encryption), `did:key` and `did:web` document
 * resolving, W3C credential issuing/presentation/verification, and C2PA embedding/verification.
 *
 * Ed25519 usage example:
 *
 * ```ts
 * import {
 *   ContextLoader,
 *   Document,
 *   PrivateEd25519,
 *   verifyJWS
 * } from "@vaultie/teddybear";
 *
 * // Private Ed25519 keys can be generated from CSPRNG or
 * // restored from existing raw key bytes.
 * const privateKey = PrivateEd25519.generate();
 *
 * // You can export various different keys in multiple formats.
 * //
 * // Be aware, that all Teddybear private keys don't contain
 * // the associated DID document identifier or controller.
 * const ed25519Bytes = privateKey.toBytes();
 * const publicJwk = privateKey.toPublicJWK();
 * const privateJwk = privateKey.toPrivateJWK();
 * const didKey = privateKey.toDIDKey();
 *
 * // You can convert private Ed25519 keys to public Ed25519 keys
 * // by providing the related DID document identifier and controller.
 * const publicKey = privateKey.toPublicKey("did:web:example.com", "did:web:example.com");
 *
 * // It is possible to convert a private Ed25519 key into a private
 * // X25519 key.
 * const x25519 = privateKey.toX25519PrivateKey();
 *
 * // Private Ed25519 keys can be used to sign JWS, ...
 * const jws = privateKey.signJWS("testvalue", true);
 *
 * // ...issue verifiable credentials, ...
 * const contextLoader = new ContextLoader();
 * const verifiableCredential = await key.issueVC(
 *   "did:web:example.com#key-1",
 *   {
 *     "@context": ["https://www.w3.org/ns/credentials/v2"],
 *     type: ["VerifiableCredential"],
 *     id: "https://example.com/test",
 *     issuer: "did:web:example.com",
 *     issuanceDate: new Date().toISOString(),
 *     credentialSubject: {}
 *   },
 *   contextLoader,
 * );
 *
 * // ...present them, ...
 * const vp = await key.presentVP(
 *   "did:web:example.com#key-1",
 *   {
 *     "@context": ["https://www.w3.org/ns/credentials/v2"],
 *     type: ["VerifiablePresentation"],
 *     verifiableCredential,
 *   },
 *   contextLoader,
 *   undefined,
 *   undefined,
 * );
 *
 * // ...and embed signed C2PA manifests into files
 * const { signedPayload } = new C2PABuilder()
 *   .setManifestDefinition({
 *     title: "Test Image",
 *     assertions: [
 *       {
 *         label: "stds.schema-org.CreativeWork",
 *         data: {
 *           "@context": "http://schema.org/",
 *           "@type": "CreativeWork",
 *           url: "https://example.com",
 *         },
 *         kind: "Json",
 *       },
 *     ],
 *   })
 *   .sign(
 *     key,
 *     new Uint8Array(certificate),
 *     new Uint8Array(image),
 *     "image/jpeg",
 *   );
 *
 * // Resolve a DID document. This is essentially an entrypoint
 * // to almost all Teddybear operations.
 * const document = await Document.resolve("did:web:example.com");
 *
 * // Resolved DID document may contain multiple keys with different
 * // algorithms within it, so usually you would select one based on
 * // key types, operation requirements, etc.
 * const vm = document.verificationMethods().authentication?.[0]!;
 * const resolvedKey = document.getEd25519VerificationMethod(vm);
 *
 * // Public Ed25519 keys can be used to verify JWS signatures
 * const { jwk, payload } = verifyJWS(jws);
 * ```
 *
 * X25519 usage example:
 *
 * ```ts
 * import {
 *   Document,
 *   encryptAES
 * } from "@vaultie/teddybear";
 *
 * const document = await Document.resolve("did:web:example.com");
 *
 * const vm = document.verificationMethods().keyAgreement?.[0]!;
 * const resolvedKey = document.getX25519VerificationMethod(vm);
 *
 * // X25519 public keys can be used to encrypt data for multiple recipients
 * // using JWE format. You can pass all recipient keys as an array.
 * // To encrypt with XChaCha20-Poly1305 use "encryptChaCha20" instead.
 * const encrypted = encryptAES(value, [resolvedKey]);
 * ```
 *
 * @module
 * @packageDocumentation
 */
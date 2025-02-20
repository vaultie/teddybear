# Teddybear - Cryptographic Toolkit for JS/TS  

Teddybear is a **JavaScript/TypeScript suite of cryptographic utilities**, shipped as a single **ESM/CJS-compatible** package.  

It provides a robust set of tools for working with **verifiable credentials**, **decentralized identifiers (DIDs)**, and **secure cryptographic operations**.

---

## Features  

### **Key Management**  
- Supports **Ed25519** (for digital signatures) and **X25519** (for encryption).  
- Perform **JWS** (JSON Web Signature) signing and verification.  
- Encrypt and decrypt messages using **JWE** (JSON Web Encryption).  

### **DID Resolution**  
- Resolve **did:key** and **did:web** documents for decentralized identity.  

### **Verifiable Credentials (W3C Standard)**  
- Issue, present, and verify **W3C-compliant** verifiable credentials.  

### **C2PA (Content Provenance & Authenticity)**  
- Embed and verify **C2PA metadata** to ensure content authenticity.  

### **WebAssembly (WASM) Support**  
- Works seamlessly in both **browser** and **Node.js** environments.  



## Installation  

Install **Teddybear** via **Yarn**:  

```sh
yarn add @vaultie/teddybear
```
--- 
## Usage
### Key Generation
``` sh 
import { generateKeyPair } from "@vaultie/teddybear";

const { publicKey, privateKey } = generateKeyPair();
console.log("Public Key:", publicKey);
console.log("Private Key:", privateKey);
``` 
### JWS Signing & Verification
``` sh 
import { signJWS, verifyJWS } from "@vaultie/teddybear";

const payload = { data: "Hello, secure world!" };
const signature = await signJWS(payload, privateKey);
const isValid = await verifyJWS(signature, publicKey);

console.log("Signature:", signature);
console.log("Valid:", isValid);

```
### JWE Encryption & Decryption
``` sh 
import { encryptJWE, decryptJWE } from "@vaultie/teddybear";

const message = "Sensitive data";
const encrypted = await encryptJWE(message, publicKey);
const decrypted = await decryptJWE(encrypted, privateKey);

console.log("Encrypted:", encrypted);
console.log("Decrypted:", decrypted);


```
### DID Resolution
``` sh
import { resolveDID } from "@vaultie/teddybear";

const didDocument = await resolveDID("did:key:z6Mk...");
console.log(didDocument);

```
### Issuing a Verifiable Credential
``` sh 
import { issueCredential } from "@vaultie/teddybear";

const credential = await issueCredential({
  issuer: "did:web:example.com",
  subject: "did:key:z6Mk...",
  claim: { name: "Alice", age: 25 },
});

console.log("Issued Credential:", credential);

```


## Testing 
### P-256 Key Generation
``` sh
import { PrivateSecp256r1 } from "@vaultie/teddybear";

const key = PrivateSecp256r1.generate();
console.log("Public JWK:", key.toPublicJWK().toJSON());
console.log("Private JWK:", key.toPrivateJWK().toJSON());
```
### Encryption & Decryption
``` sh 

import { generateP256 } from "./utils";
import { PublicSecp256r1 } from "@vaultie/teddybear";

const { privateKey, publicKey, vm } = await generateP256();
const value = new TextEncoder().encode("Hello, world");

const encrypted = PublicSecp256r1.encryptAES(value, [publicKey]);
const decrypted = privateKey.decryptAES(vm, encrypted);

console.log("Decrypted message:", new TextDecoder().decode(decrypted));

```
### JWS Signing & Verification

``` sh 
import { PrivateSecp256r1, verifyJWS } from "@vaultie/teddybear";

const key = PrivateSecp256r1.generate();
const jws = key.signJWS("testvalue");

const { payload } = verifyJWS(jws);
console.log("Verified payload:", new TextDecoder().decode(payload));
```

## Building from source 
- Ensure that you have Nix installed with flakes support enabled.
``` sh 
nix build
``` 

## License
- You may choose either MIT license or Apache License, Version 2.0.


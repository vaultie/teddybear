import { PrivateEd25519, PublicEd25519, encrypt } from '@vaultie/teddybear-node'
import { describe, it, expect } from 'vitest'

// @ts-expect-error Library without TS definitions
import { Cipher } from '@digitalbazaar/minimal-cipher'

// @ts-expect-error Library without TS definitions
import { Ed25519VerificationKey2020 } from '@digitalbazaar/ed25519-verification-key-2020'

// @ts-expect-error Library without TS definitions
import { X25519KeyAgreementKey2020 } from '@digitalbazaar/x25519-key-agreement-key-2020'

describe('can execute JWE operations', () => {
  it('can encrypt and decrypt for a single key', async () => {
    const key = await PrivateEd25519.generate()

    const value = new TextEncoder().encode('Hello, world')
    const encrypted = encrypt(value, [key.toX25519PublicJWK()])
    expect(key.decrypt(encrypted)).toStrictEqual(value)
  })

  it('can encrypt and decrypt for multiple keys', async () => {
    const firstKey = await PublicEd25519.fromDID('did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R')
    const secondKey = await PublicEd25519.fromDID('did:key:z6MkqWhsS8uVAnUpgKUZhZAHz2ioDFbBaR6eZPM8UkUQcrEg')
    const thirdKey = await PrivateEd25519.generate()

    const value = new TextEncoder().encode('Hello, world')
    const encrypted = encrypt(value, [
      firstKey.toX25519PublicJWK(),
      secondKey.toX25519PublicJWK(),
      thirdKey.toX25519PublicJWK()
    ])

    expect(thirdKey.decrypt(encrypted)).toStrictEqual(value)
  })

  it('other libraries can decrypt JWEs', async () => {
    const data = new TextEncoder().encode('Hello, world')

    const keyPair = await Ed25519VerificationKey2020.generate()
    const keyAgreementKey = await X25519KeyAgreementKey2020.fromEd25519VerificationKey2020({ keyPair })

    const did = `did:key:${keyPair.fingerprint()}`
    keyAgreementKey.controller = did
    keyAgreementKey.id = `${did}#${keyAgreementKey.fingerprint()}`

    const firstKey = await PublicEd25519.fromDID(did)
    const secondKey = await PrivateEd25519.generate()

    const jwe = encrypt(data, [
      firstKey.toX25519PublicJWK(),
      secondKey.toX25519PublicJWK()
    ])

    const cipher = new Cipher({
      version: 'fips'
    })

    expect(await cipher.decrypt({ jwe, keyAgreementKey })).toStrictEqual(data)
  })

  it('can decrypt JWEs from other libraries', async () => {
    const data = new TextEncoder().encode('Hello, world')

    const firstKey = await PublicEd25519.fromDID('did:key:z6MkmpNwNTy4ATx87tZWHqSwNf1ZdeQrBHFWyhtvUwqrt32R')
    const secondKey = await PrivateEd25519.generate()

    const recipients = [
      { header: { kid: firstKey.x25519DID(), alg: 'ECDH-ES+A256KW' } },
      { header: { kid: secondKey.x25519DID(), alg: 'ECDH-ES+A256KW' } }
    ]

    const documents: Record<string, object> = {
      [firstKey.x25519DID()]: firstKey.document().keyAgreement[0],
      [secondKey.x25519DID()]: secondKey.document().keyAgreement[0]
    }

    const keyResolver = async ({ id }: { id: string }) => documents[id]

    const cipher = new Cipher({
      version: 'fips'
    })

    const jwe = await cipher.encrypt({ data, recipients, keyResolver })

    expect(secondKey.decrypt(jwe)).toStrictEqual(data)
  })
})

import { PrivateEd25519, verifyJWS } from '@vaultie/teddybear-node'
import { CompactSign, JWK, compactVerify, exportJWK, generateKeyPair, importJWK } from 'jose'
import { describe, it, expect } from 'vitest'

describe('can execute common private key operations', () => {
  it('can generate a new key', async () => await PrivateEd25519.generate())

  it('can extract DID values', async () => {
    const key = await PrivateEd25519.generate()
    const documentDID = key.documentDID()

    expect(documentDID).toMatch(/did:key:z6Mk.*/)
    expect(key.ed25519DID()).toMatch(new RegExp(`${documentDID}#z6Mk.*`))
    expect(key.x25519DID()).toMatch(new RegExp(`${documentDID}#z6LS.*`))
  })

  it('can extract JWK values', async () => {
    const key = await PrivateEd25519.generate()

    key.toEd25519PublicJWK()
    key.toX25519PublicJWK()
    key.toEd25519PrivateJWK()
    key.toX25519PrivateJWK()
  })

  it('can sign JWS values', async () => {
    const key = await PrivateEd25519.generate()

    const jws = key.signJWS('testvalue', true)
    const { payload } = await compactVerify(jws, await importJWK(key.toEd25519PublicJWK().toJSON() as JWK))
    expect(new TextDecoder().decode(payload)).toStrictEqual('testvalue')
  })

  it('can extract JWS payload', async () => {
    const key = await PrivateEd25519.generate()

    const jws = key.signJWS('testvalue', true)

    const { jwk, payload } = verifyJWS(jws)
    expect(jwk.toJSON()).toStrictEqual(key.toEd25519PublicJWK().toJSON())
    expect(new TextDecoder().decode(payload)).toStrictEqual('testvalue')
  })

  it('can sign JWS values without embedded keys', async () => {
    const key = await PrivateEd25519.generate()

    const jws = key.signJWS('testvalue', false)

    const { jwk, payload } = verifyJWS(jws, key.toEd25519PublicJWK())
    expect(jwk).toBeUndefined()
    expect(new TextDecoder().decode(payload)).toStrictEqual('testvalue')
  })

  it('can use valid JWS values from other libraries', async () => {
    const { publicKey, privateKey } = await generateKeyPair('EdDSA')
    const publicKeyJWK = await exportJWK(publicKey)

    const jws = await new CompactSign(new TextEncoder().encode('Hello, world'))
      .setProtectedHeader({ alg: 'EdDSA', jwk: publicKeyJWK })
      .sign(privateKey)

    const { jwk, payload } = verifyJWS(jws)
    expect(jwk.toJSON()).toStrictEqual(publicKeyJWK)
    expect(new TextDecoder().decode(payload)).toStrictEqual('Hello, world')
  })

  it('can reject JWS values with invalid embedded JWKs from other libraries', async () => {
    const { privateKey } = await generateKeyPair('EdDSA')
    const { publicKey } = await generateKeyPair('EdDSA')

    const jws = await new CompactSign(new TextEncoder().encode('Hello, world'))
      .setProtectedHeader({ alg: 'EdDSA', jwk: await exportJWK(publicKey) })
      .sign(privateKey)

    expect(() => verifyJWS(jws)).toThrow()
  })

  it('can reject invalid JWS values', async () => {
    expect(() => verifyJWS('123')).toThrow()
  })
})

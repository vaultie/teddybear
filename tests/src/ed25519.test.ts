import { PrivateEd25519 } from '@vaultie/teddybear-node'
import { JWK, compactVerify, importJWK } from 'jose'
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

  it('can sign jws values', async () => {
    const key = await PrivateEd25519.generate()

    const jws = key.signJWS('testvalue')
    const { payload } = await compactVerify(jws, await importJWK(key.toEd25519PublicJWK().toJSON() as JWK))
    expect(new TextDecoder().decode(payload)).toStrictEqual('testvalue')
  })
})

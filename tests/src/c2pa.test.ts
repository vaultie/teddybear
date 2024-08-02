import { C2PABuilder, PrivateEd25519, verifyC2PA } from '@vaultie/teddybear'
import { readFileSync } from 'fs'
import { describe, expect, it } from 'vitest'

const image = readFileSync(process.env.placeholderImage!)
const pdf = readFileSync(process.env.placeholderPdf!)
const certificate = readFileSync(process.env.certificate!)

describe('can execute C2PA operations', () => {
  it('can sign an image', async () => {
    // This key should correspond to the certificate private key
    const keyBytes = Buffer.from('5ff5e2393a44256abe197c82742366ff2f998f6822980e726f8fd16d6bd07eb1', 'hex')

    const key = await PrivateEd25519.fromBytes(new Uint8Array(keyBytes))

    const { signedPayload } = new C2PABuilder()
      .sign(key, new Uint8Array(certificate), new Uint8Array(image), 'image/jpeg', {
        title: 'Test Image',
        assertions: [
          {
            label: 'stds.schema-org.CreativeWork',
            data: {
              '@context': 'http://schema.org/',
              '@type': 'CreativeWork',
              url: 'https://example.com'
            },
            kind: 'Json'
          }
        ]
      })

    const { validationErrors } = verifyC2PA(signedPayload, 'image/jpeg')

    expect(validationErrors).toHaveLength(0)
  })

  it('can sign a PDF file', async () => {
    // This key should correspond to the certificate private key
    const keyBytes = Buffer.from('5ff5e2393a44256abe197c82742366ff2f998f6822980e726f8fd16d6bd07eb1', 'hex')

    const key = await PrivateEd25519.fromBytes(new Uint8Array(keyBytes))

    const { signedPayload } = new C2PABuilder()
      .sign(key, new Uint8Array(certificate), new Uint8Array(pdf), 'application/pdf', {
        title: 'Test PDF',
        assertions: [
          {
            label: 'stds.schema-org.CreativeWork',
            data: {
              '@context': 'http://schema.org/',
              '@type': 'CreativeWork',
              url: 'https://example.com'
            },
            kind: 'Json'
          }
        ]
      })

    const { validationErrors } = verifyC2PA(signedPayload, 'application/pdf')

    expect(validationErrors).toHaveLength(0)
  })

  it('can verify a damaged file', async () => {
    // This key should correspond to the certificate private key
    const keyBytes = Buffer.from('5ff5e2393a44256abe197c82742366ff2f998f6822980e726f8fd16d6bd07eb1', 'hex')

    const key = await PrivateEd25519.fromBytes(new Uint8Array(keyBytes))

    const { signedPayload } = new C2PABuilder()
      .sign(key, new Uint8Array(certificate), new Uint8Array(pdf), 'application/pdf', {
        title: 'Test PDF',
        assertions: [
          {
            label: 'stds.schema-org.CreativeWork',
            data: {
              '@context': 'http://schema.org/',
              '@type': 'CreativeWork',
              url: 'https://example.com'
            },
            kind: 'Json'
          }
        ]
      })

    const { validationErrors } = verifyC2PA(
      signedPayload.fill(123, 500, 600),
      'application/pdf'
    )

    expect(validationErrors).toHaveLength(1)
    expect(validationErrors[0].code).toStrictEqual('assertion.dataHash.mismatch')
  })
})

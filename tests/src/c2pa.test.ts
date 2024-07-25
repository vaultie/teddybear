import { PrivateEd25519 } from '@vaultie/teddybear'
import { readFileSync } from 'fs'
import { describe, it } from 'vitest'

const image = readFileSync(process.env.placeholderImage!)
const certificate = readFileSync(process.env.certificate!)

describe('can execute C2PA operations', () => {
  it('can sign a C2PA manifest', async () => {
    // This key should correspond to the certificate private key
    const keyBytes = Buffer.from('5ff5e2393a44256abe197c82742366ff2f998f6822980e726f8fd16d6bd07eb1', 'hex')

    const key = await PrivateEd25519.fromBytes(new Uint8Array(keyBytes))

    key.embedC2PAManifest(new Uint8Array(certificate), new Uint8Array(image), 'image/jpeg', {
      title: 'Hello World',
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
      ],
      claim_generator_info: [
        { name: 'Teddybear' }
      ]
    })
  })
})

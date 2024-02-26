import { ContextLoader } from '@vaultie/teddybear-node'
import { describe, it } from 'vitest'

describe('can execute verifiable credentials operations', () => {
  it('can create a default context loader', () => new ContextLoader())
  it('can create a custom context loader', () => new ContextLoader({
    'https://example.com': JSON.stringify({
      '@context': {
        '@version': 1.1,
        '@protected': true,

        VaultieRecordReference: {
          '@id': 'https://vaultie.io/VaultieRecordReference/v1',
          '@context': {
            '@version': 1.1,
            '@protected': true,
            id: '@id',
            record: { '@id': 'https://vaultie.io/VaultieRecordReference/v1#record', '@type': 'https://schema.org#Text' }
          }
        }
      }
    })
  }))
})

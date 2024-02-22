import { StatusListCredential } from '@vaultie/teddybear-node'
import { describe, expect, it } from 'vitest'

describe('can execute status list operations', () => {
  it('can create an empty status list and serialize it', async () => {
    const statusList = new StatusListCredential()
    const serialized = statusList.toJSON()

    expect(serialized).toHaveProperty('encoded_list')
    expect(serialized).toHaveProperty('status_purpose', 'revocation')
  })

  it('can revoke a credential', async () => {
    const statusList = new StatusListCredential()

    expect(statusList.isRevoked(0)).toBeFalsy()
    statusList.revoke(0)
    expect(statusList.isRevoked(0)).toBeTruthy()
  })

  it('can revoke a lot of credentials', async () => {
    const statusList = new StatusListCredential()

    const indices = Array.from({ length: 4096 }, () => Math.floor(Math.random() * 131072))

    for (const idx of indices) {
      statusList.revoke(idx)
    }

    const serialized = statusList.toJSON()

    expect(serialized).toHaveProperty('encoded_list')
    expect(serialized).toHaveProperty('status_purpose', 'revocation')
  })
})

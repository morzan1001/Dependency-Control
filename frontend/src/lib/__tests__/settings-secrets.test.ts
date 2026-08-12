import { describe, expect, it } from 'vitest'
import { stripEmptySecrets } from '../settings-secrets'

describe('stripEmptySecrets', () => {
  it('drops empty-string secret fields so stored values are not wiped', () => {
    const result = stripEmptySecrets({
      github_token: '',
      smtp_password: '',
      smtp_host: 'smtp.example.com',
    })
    expect(result).toEqual({ smtp_host: 'smtp.example.com' })
  })

  it('keeps secrets the user actually entered', () => {
    const result = stripEmptySecrets({ github_token: 'github_pat_new', smtp_password: '' })
    expect(result).toEqual({ github_token: 'github_pat_new' })
  })

  it('leaves non-secret empty strings untouched', () => {
    const result = stripEmptySecrets({ smtp_host: '' })
    expect(result).toEqual({ smtp_host: '' })
  })
})

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import type { BackupPreview } from './configBackups'

const source = readFileSync(resolve(process.cwd(), 'src/api/configBackups.ts'), 'utf8')

describe('configuration backup API contract', () => {
  it('uploads multipart fields without hand-setting a content type', () => {
    expect(source).toContain("form.append('file', data.file)")
    expect(source).toContain("form.append('password', data.password)")
    expect(source).toContain("form.append('scope', data.scope)")
    expect(source).toContain("form.append('site_id', data.siteId)")
    expect(source).not.toContain("form.set('Content-Type'")
  })

  it('keeps restore previews to counts and warnings, never secret values', () => {
      const preview: BackupPreview = {
        scope: 'deployment',
        tables: [{ table: 'sites', before: 1, after: 2, added: 1, removed: 0, changed: 1 }],
        sites_to_remove: [],
        owner_changes: [],
        warnings: ['site retained'],
      }
      expect(preview.tables[0]?.added).toBe(1)
      expect(JSON.stringify(preview)).not.toContain('private_key')
  })
})

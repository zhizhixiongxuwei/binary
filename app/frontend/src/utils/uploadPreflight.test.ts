import { describe, expect, it } from 'vitest'

import {
  inputCategoryAccept,
  nativePickerAcceptAttributes,
  preflightUploadFile,
} from '@/utils/uploadPreflight'

function binaryFile(name: string, signature: number[], type: string): File {
  return new File([Uint8Array.from(signature)], name, { type })
}

describe('inputCategoryAccept', () => {
  it('does not restrict the native picker for binary files', () => {
    expect(inputCategoryAccept.binary).toBeUndefined()
    expect(nativePickerAcceptAttributes('binary')).toEqual({})
  })

  it('keeps native picker hints for archives and containers', () => {
    expect(inputCategoryAccept.archive).toContain('.zip')
    expect(inputCategoryAccept.archive).toContain('.iso')
    expect(inputCategoryAccept.archive).toContain('.img')
    expect(inputCategoryAccept.archive).toContain('.ext4')
    expect(inputCategoryAccept.container).toContain('.tar')
    expect(nativePickerAcceptAttributes('archive')).toHaveProperty('accept')
    expect(nativePickerAcceptAttributes('container')).toHaveProperty('accept')
  })
})

describe('preflightUploadFile', () => {
  it('keeps the unified picker open for server-side content detection', async () => {
    const result = await preflightUploadFile(
      new File(['server decides'], 'disk.ext4', {
        type: 'application/octet-stream',
      }),
    )

    expect(result).toEqual({ accepted: true })
  })

  it('still rejects explicitly known unsupported signatures in unified mode', async () => {
    const result = await preflightUploadFile(
      binaryFile(
        'package.cab',
        [0x4d, 0x53, 0x43, 0x46],
        'application/octet-stream',
      ),
    )

    expect(result.accepted).toBe(false)
    expect(result.detectedFormat).toBe('CAB')
  })

  it.each([
    {
      name: 'sample-elf',
      type: 'application/x-executable',
      signature: [0x7f, 0x45, 0x4c, 0x46],
      format: 'ELF',
    },
    {
      name: 'sample-macho',
      type: 'application/x-mach-binary',
      signature: [0xcf, 0xfa, 0xed, 0xfe],
      format: 'Mach-O / Java CLASS',
    },
  ])('accepts extensionless $format content as binary', async (fixture) => {
    const result = await preflightUploadFile(
      binaryFile(fixture.name, fixture.signature, fixture.type),
      'binary',
    )

    expect(result).toEqual({ accepted: true, detectedFormat: fixture.format })
  })

  it('rejects an unknown file even though the binary picker has no accept filter', async () => {
    const result = await preflightUploadFile(
      new File(['plain text'], 'notes.txt', { type: 'text/plain' }),
      'binary',
    )

    expect(result).toEqual({
      accepted: false,
      message: 'notes.txt：无法识别为当前支持的二进制格式',
    })
  })

  it('keeps extension-based fallback for formats whose magic varies by runtime', async () => {
    const result = await preflightUploadFile(
      binaryFile('version-specific.pyc', [0x00, 0x00, 0x0d, 0x0a], 'application/octet-stream'),
      'binary',
    )

    expect(result).toEqual({ accepted: true })
  })

  it.each(['vulnerable-binaries.iso', 'vulnerable-binaries.img'])(
    'routes ISO 9660 content in %s to archive import',
    async (name) => {
      const body = new Uint8Array(40 * 1_024)
      const offset = 16 * 2_048
      body[offset] = 1
      body.set(Array.from('CD001').map((character) => character.charCodeAt(0)), offset + 1)
      body[offset + 6] = 1

      const result = await preflightUploadFile(
        new File([body], name, { type: 'application/octet-stream' }),
        'archive',
      )

      expect(result).toEqual({ accepted: true, detectedFormat: 'ISO 9660' })
    },
  )

  it('routes EXT4 content to the read-only archive workflow', async () => {
    const body = new Uint8Array(2 * 1_024)
    body[1_024 + 0x38] = 0x53
    body[1_024 + 0x39] = 0xef

    const result = await preflightUploadFile(
      new File([body], 'vulnerable-binaries.ext4', { type: 'application/octet-stream' }),
      'archive',
    )

    expect(result).toEqual({ accepted: true, detectedFormat: 'EXT4' })
  })
})

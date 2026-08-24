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
    expect(inputCategoryAccept.container).toContain('.tar')
    expect(nativePickerAcceptAttributes('archive')).toHaveProperty('accept')
    expect(nativePickerAcceptAttributes('container')).toHaveProperty('accept')
  })
})

describe('preflightUploadFile', () => {
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
})

import { describe, expect, it } from 'vitest'
import { analysisEngineLabel, analysisMessage } from './analysisPresentation'

describe('analysis business labels', () => {
  it.each([
    ['Trivy', '漏洞检测引擎'], ['native-decompiler', '原生二进制反编译引擎'],
    ['Ghidra', '原生二进制反编译引擎'], ['Vineflower', 'Java 反编译引擎'],
    ['CFR', 'Java 反编译引擎'], ['JADX', 'Android 反编译引擎'],
    ['pycdc', 'Python 字节码反编译引擎'],
  ])('presents %s through a business capability', (id, label) => {
    expect(analysisEngineLabel(id)).toBe(label)
  })

  it('keeps unknown identities and only translates known tool words in generated prose', () => {
    expect(analysisEngineLabel('custom-engine')).toBe('custom-engine')
    expect(analysisEngineLabel('JADX 字段契约示例')).toBe('Android 反编译引擎 字段契约示例')
    expect(analysisMessage('Ghidra 处理失败；pycdc 不可用')).toBe('原生二进制反编译引擎 处理失败；Python 字节码反编译引擎 不可用')
    expect(analysisMessage('trivially ghidra_helper')).toBe('trivially ghidra_helper')
  })
})

import { describe, expect, it } from 'vitest'
import { findSourceFunctions } from './sourceFunctions'

describe('findSourceFunctions', () => {
  it('locates Java methods and excludes control flow statements', () => {
    expect(findSourceFunctions([
      'public class Store {',
      '  public Cursor queryRecords() {',
      '    if (ready()) { return database.rawQuery("SELECT *", null); }',
      '  }',
      '  void close() {',
      '    database.close();',
      '  }',
      '}',
    ].join('\n'))).toEqual([
      { name: 'queryRecords', startLine: 2, endLine: 4 },
      { name: 'close', startLine: 5, endLine: 7 },
    ])
  })

  it('locates Python definitions without consuming the next peer', () => {
    expect(findSourceFunctions('def first():\n    return 1\n\ndef second():\n    return 2\n')).toEqual([
      { name: 'first', startLine: 1, endLine: 3 },
      { name: 'second', startLine: 4, endLine: 6 },
    ])
  })
})

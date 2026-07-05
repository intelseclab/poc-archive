import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readdirSync, rmSync } from 'fs';
import { join } from 'path';
import { WORKSPACE } from '../lib/config.mjs';

// Import functions from local-mcp.mjs
import {
  nl, compactDiff, applyEdit, fileUriToPath, pathToFileUri,
  treeDir, findBlock, listResources, readResource, scoreResults,
  _isBinary as isBinary, _ok as ok, _isExcluded as isExcluded,
  _sanitizeKey as sanitizeKey, _atomicWrite as atomicWrite,
  _cachedRead as cachedRead, _invalidateCache as invalidateCache
} from '../local-mcp.mjs';

describe('nl()', () => {
  it('should convert CRLF to LF', () => {
    assert.equal(nl('hello\r\nworld'), 'hello\nworld');
  });
  it('should handle null/undefined', () => {
    assert.equal(nl(null), '');
    assert.equal(nl(undefined), '');
    assert.equal(nl(''), '');
  });
  it('should leave LF as-is', () => {
    assert.equal(nl('hello\nworld'), 'hello\nworld');
  });
  it('should handle mixed line endings', () => {
    assert.equal(nl('a\r\nb\nc\r\nd'), 'a\nb\nc\nd');
  });
});

describe('compactDiff()', () => {
  it('should count additions and deletions', () => {
    const diff = [
      '--- old.txt',
      '+++ new.txt',
      '@@ -1,3 +1,4 @@',
      ' line1',
      '+added line',
      '-removed line',
      ' unchanged',
      ''
    ].join('\n');
    assert.equal(compactDiff(diff), '+1/-1 lines');
  });
  it('should return +0/-0 for empty diff', () => {
    assert.equal(compactDiff(''), '+0/-0 lines');
  });
  it('should not count diff headers', () => {
    const diff = [
      '--- a/file',
      '+++ b/file',
      '@@ -0,0 +1 @@',
      '+new file',
      ''
    ].join('\n');
    assert.equal(compactDiff(diff), '+1/-0 lines');
  });
  it('should handle multiple hunks', () => {
    const diff = [
      '--- a/file', '+++ b/file',
      '@@ -1 +1,2 @@',
      ' base',
      '+add1',
      '@@ -10 +11,2 @@',
      '-del1',
      '+add2',
      ''
    ].join('\n');
    assert.equal(compactDiff(diff), '+2/-1 lines');
  });
});

describe('applyEdit()', () => {
  it('should replace exact match', () => {
    const result = applyEdit('hello world', 'world', 'there');
    assert.equal(result, 'hello there');
  });
  it('should handle multi-line exact match', () => {
    const content = 'line1\nline2\nline3';
    const result = applyEdit(content, 'line2', 'changed');
    assert.equal(result, 'line1\nchanged\nline3');
  });
  it('should use fuzzy match when indentation differs', () => {
    const content = '  hello\n  world\n  foo';
    const result = applyEdit(content, 'world', 'there');
    assert.equal(result, '  hello\n  there\n  foo');
  });
  it('should preserve indentation in fuzzy match', () => {
    const content = 'function a() {\n    console.log("hi");\n}';
    const result = applyEdit(content, 'console.log("hi");', 'console.log("hello");');
    assert.equal(result, 'function a() {\n    console.log("hello");\n}');
  });
  it('should throw MATCH_NOT_FOUND when no match', () => {
    assert.throws(
      () => applyEdit('hello world', 'nonexistent', 'x'),
      e => e.type === 'MATCH_NOT_FOUND'
    );
  });
  it('should replace newText with empty string', () => {
    const result = applyEdit('hello world foo', 'world', '');
    assert.equal(result, 'hello  foo');
  });
});

describe('fileUriToPath()', () => {
  it('should convert file:// URI to path', () => {
    const result = fileUriToPath('file:///home/user/test.txt');
    // On non-Windows: /home/user/test.txt
    if (process.platform !== 'win32') {
      assert.equal(result, '/home/user/test.txt');
    }
  });
  it('should handle encoded characters', () => {
    const result = fileUriToPath('file:///home/user/file%20name.txt');
    if (process.platform !== 'win32') {
      assert.equal(result, '/home/user/file name.txt');
    }
  });
  it('should throw INVALID_URI for non-file URIs', () => {
    assert.throws(
      () => fileUriToPath('http://example.com'),
      e => e.type === 'INVALID_URI'
    );
  });
  it('should throw INVALID_URI for empty string', () => {
    assert.throws(
      () => fileUriToPath(''),
      e => e.type === 'INVALID_URI'
    );
  });
});

describe('pathToFileUri()', () => {
  it('should convert absolute path to file:// URI', () => {
    const result = pathToFileUri('/home/user/test.txt');
    if (process.platform !== 'win32') {
      assert.equal(result, 'file:///home/user/test.txt');
    }
  });
  it('should resolve relative paths', () => {
    const result = pathToFileUri('.');
    assert.ok(result.startsWith('file://'));
  });
});

describe('findBlock()', () => {
  it('should find function by name', () => {
    const lines = [
      'function foo() {',
      '  return 42;',
      '}'
    ];
    const block = findBlock(lines, 'foo');
    assert.ok(block);
    assert.equal(block.start, 0);
    assert.equal(block.end, 2);
  });
  it('should find const arrow function', () => {
    const lines = [
      'const foo = () => {',
      '  return 42;',
      '}'
    ];
    const block = findBlock(lines, 'foo');
    assert.ok(block);
    assert.equal(block.start, 0);
    assert.equal(block.end, 2);
  });
  it('should return null for missing function', () => {
    const lines = ['const x = 1;'];
    const block = findBlock(lines, 'nonexistent');
    assert.equal(block, null);
  });
  it('should handle nested braces', () => {
    const lines = [
      'function outer() {',
      '  if (true) {',
      '    inner();',
      '  }',
      '}'
    ];
    const block = findBlock(lines, 'outer');
    assert.ok(block);
    assert.equal(block.start, 0);
    assert.equal(block.end, 4);
  });
});

describe('treeDir()', () => {
  let tmpDir;
  before(() => {
    tmpDir = mkdtempSync(join(WORKSPACE, '.tree-test-'));
    mkdirSync(join(tmpDir, 'subdir'), { recursive: true });
    writeFileSync(join(tmpDir, 'a.txt'), 'a');
    writeFileSync(join(tmpDir, 'b.txt'), 'b');
    writeFileSync(join(tmpDir, 'subdir', 'c.txt'), 'c');
  });
  after(() => { rmSync(tmpDir, { recursive: true, force: true }); });

  it('should list files with tree structure', () => {
    const result = treeDir(tmpDir, 2);
    assert.ok(result.includes('a.txt'));
    assert.ok(result.includes('b.txt'));
    assert.ok(result.includes('subdir'));
    assert.ok(result.includes('└──') || result.includes('├──'));
  });

  it('should limit depth', () => {
    const result = treeDir(tmpDir, 1);
    assert.ok(result.includes('subdir'));
    if (readdirSync(tmpDir).length > 0) {
      assert.ok(result.includes('...') || result.includes('c.txt'));
    }
  });
});

describe('listResources()', () => {
  it('should return workspace resource', () => {
    const resources = listResources();
    assert.ok(Array.isArray(resources));
    assert.ok(resources.length >= 1);
    assert.ok(resources[0].uri.startsWith('file://'));
    assert.equal(resources[0].name, 'Workspace root');
    assert.equal(resources[0].mimeType, 'inode/directory');
  });
});

describe('readResource()', () => {
  let tmpFile, tmpDir;

  before(() => {
    tmpDir = mkdtempSync(join(WORKSPACE, '.res-test-'));
    tmpFile = join(tmpDir, 'test.json');
    writeFileSync(tmpFile, JSON.stringify({ key: 'value' }));
  });
  after(() => { rmSync(tmpDir, { recursive: true, force: true }); });

  it('should read a file and detect JSON mime type', () => {
    const result = readResource('file://' + tmpFile);
    assert.equal(result.mimeType, 'application/json');
    assert.ok(result.text.includes('"key"'));
  });

  it('should read a directory', () => {
    const result = readResource('file://' + tmpDir);
    assert.equal(result.mimeType, 'inode/directory');
    assert.ok(typeof result.text === 'string');
  });
});

describe('readResource() MIME types', () => {
  let tmpDir;
  before(() => {
    tmpDir = mkdtempSync(join(WORKSPACE, '.mime-test-'));
    writeFileSync(join(tmpDir, 'readme.md'), '# Title\ncontent');
    writeFileSync(join(tmpDir, 'script.js'), 'const x = 1;');
    writeFileSync(join(tmpDir, 'plain.txt'), 'plain text');
  });
  after(() => { rmSync(tmpDir, { recursive: true, force: true }); });

  it('should detect markdown mime type', () => {
    const result = readResource('file://' + join(tmpDir, 'readme.md'));
    assert.equal(result.mimeType, 'text/markdown');
  });

  it('should detect javascript mime type', () => {
    const result = readResource('file://' + join(tmpDir, 'script.js'));
    assert.equal(result.mimeType, 'text/javascript');
  });

  it('should detect text mime type for plain txt', () => {
    const result = readResource('file://' + join(tmpDir, 'plain.txt'));
    assert.equal(result.mimeType, 'text/plain');
  });
});

describe('scoreResults()', () => {
  it('should sort by relevance with exact match first', () => {
    const result = scoreResults(['src/util.js', 'util.js', 'test/util.test.js'], 'util.js');
    assert.equal(result[0], 'util.js');
  });

  it('should return empty array for empty input', () => {
    assert.deepEqual(scoreResults([], 'query'), []);
  });

  it('should handle single result', () => {
    const result = scoreResults(['file.txt'], 'file');
    assert.deepEqual(result, ['file.txt']);
  });

  it('should prefer shorter paths on equal scores', () => {
    const result = scoreResults(['src/a/deep/file.js', 'file.js'], 'file.js');
    assert.equal(result[0], 'file.js');
  });
});

describe('isBinary()', () => {
  let tmpDir;
  before(() => {
    tmpDir = mkdtempSync(join(WORKSPACE, '.bin-test-'));
    writeFileSync(join(tmpDir, 'text.txt'), 'hello world');
    // Write a file with a null byte
    const buf = Buffer.alloc(16);
    buf.write('text\x00binary');
    writeFileSync(join(tmpDir, 'binary.bin'), buf);
  });
  after(() => { rmSync(tmpDir, { recursive: true, force: true }); });

  it('should return false for text files', () => {
    assert.equal(isBinary(join(tmpDir, 'text.txt')), false);
  });

  it('should return true for files with null bytes', () => {
    assert.equal(isBinary(join(tmpDir, 'binary.bin')), true);
  });
});

describe('ok() path validation', () => {
  it('should resolve paths under workspace', () => {
    const result = ok(WORKSPACE);
    assert.equal(result, WORKSPACE);
  });

  it('should throw PERMISSION_DENIED for paths outside workspace', () => {
    assert.throws(
      () => ok('/tmp/outside'),
      e => e.type === 'PERMISSION_DENIED'
    );
  });
});

describe('sanitizeKey()', () => {
  it('should allow normal keys', () => {
    assert.equal(sanitizeKey('my-bookmark'), 'my-bookmark');
  });

  it('should throw FORBIDDEN_KEY for __proto__', () => {
    assert.throws(
      () => sanitizeKey('__proto__'),
      e => e.type === 'FORBIDDEN_KEY'
    );
  });

  it('should throw FORBIDDEN_KEY for constructor', () => {
    assert.throws(
      () => sanitizeKey('constructor'),
      e => e.type === 'FORBIDDEN_KEY'
    );
  });

  it('should throw FORBIDDEN_KEY for prototype', () => {
    assert.throws(
      () => sanitizeKey('prototype'),
      e => e.type === 'FORBIDDEN_KEY'
    );
  });
});

describe('isExcluded()', () => {
  it('should exclude node_modules directory', () => {
    assert.equal(isExcluded('/workspace/node_modules/pkg/index.js'), true);
  });

  it('should exclude .git directory', () => {
    assert.equal(isExcluded('/workspace/.git/HEAD'), true);
  });

  it('should not exclude regular files', () => {
    assert.equal(isExcluded('/workspace/src/index.js'), false);
  });
});

describe('atomicWrite() with directory', () => {
  let tmpDir;
  before(() => {
    tmpDir = mkdtempSync(join(WORKSPACE, '.atomic-test-'));
  });
  after(() => { rmSync(tmpDir, { recursive: true, force: true }); });

  it('should throw IS_DIRECTORY when writing to an existing directory', () => {
    assert.throws(
      () => atomicWrite(tmpDir, 'content'),
      e => e.type === 'IS_DIRECTORY'
    );
  });
});

describe('readCache()', () => {
  let testFile;
  let tmpDir;
  before(() => {
    tmpDir = mkdtempSync(join(WORKSPACE, '.cache-test-'));
    testFile = join(tmpDir, 'cached.txt');
    writeFileSync(testFile, 'cached content');
    // Prime the cache
    cachedRead(testFile);
  });
  after(() => { rmSync(tmpDir, { recursive: true, force: true }); });

  it('should return cached content on repeated read', () => {
    const first = cachedRead(testFile);
    const second = cachedRead(testFile);
    assert.equal(first, second);
  });

  it('should return updated content after invalidation', () => {
    invalidateCache(testFile);
    writeFileSync(testFile, 'updated content');
    const result = cachedRead(testFile);
    assert.equal(result, 'updated content');
  });
});

describe('EXCLUDE_DIRS env', () => {
  const orig = process.env.MCP_EXCLUDE;

  it('should accept MCP_EXCLUDE env var', () => {
    process.env.MCP_EXCLUDE = 'build,.next,custom_dir';
    assert.equal(process.env.MCP_EXCLUDE, 'build,.next,custom_dir');
  });

  after(() => {
    if (orig !== undefined) process.env.MCP_EXCLUDE = orig;
    else delete process.env.MCP_EXCLUDE;
  });
});

describe('createTwoFilesPatch', () => {
  it('should diff two strings', () => {
    // compactDiff parses the unified diff format
    const result = compactDiff('--- a\n+++ b\n@@ -1 +1 @@\n-old\n+new\n');
    assert.equal(result, '+1/-1 lines');
  });

  it('should handle identical content', () => {
    assert.equal(compactDiff('--- a\n+++ b\n'), '+0/-0 lines');
  });
});

describe('tool catalog', () => {
  it('should contain copy and diff tools', async () => {
    const mod = await import('../local-mcp.mjs');
    const catalog = mod._toolCatalog;
    assert.ok(catalog.find(t => t.name === 'copy'));
    assert.ok(catalog.find(t => t.name === 'diff'));
    assert.ok(catalog.find(t => t.name === 'read'));
    assert.equal(catalog.length, 13);
  });

  it('should have readOnlyHint on read/search/ls/grep/diff', async () => {
    const mod = await import('../local-mcp.mjs');
    const catalog = mod._toolCatalog;
    for (const name of ['read', 'search', 'ls', 'grep', 'diff']) {
      const t = catalog.find(x => x.name === name);
      assert.ok(t.annotations?.readOnlyHint, `${name} missing readOnlyHint`);
    }
  });

  it('should have destructiveHint on exec/move/batch/copy', async () => {
    const mod = await import('../local-mcp.mjs');
    const catalog = mod._toolCatalog;
    for (const name of ['exec', 'move', 'batch', 'copy']) {
      const t = catalog.find(x => x.name === name);
      assert.ok(t.annotations?.destructiveHint, `${name} missing destructiveHint`);
    }
  });
});

describe('scoreResults', () => {
  it('should prefer exact filename match', () => {
    const result = scoreResults(['src/util/helper.js', 'helper.js', 'test/helper.test.js'], 'helper.js');
    assert.equal(result[0], 'helper.js');
  });

  it('should return empty for empty input', () => {
    assert.deepEqual(scoreResults([], 'foo'), []);
  });
});

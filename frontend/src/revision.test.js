import test from 'node:test';
import assert from 'node:assert/strict';
import { revisionChanged } from './revision.js';

test('unchanged or not-yet-loaded revisions do not show a notice', () => {
  assert.equal(revisionChanged('', 'abc'), false);
  assert.equal(revisionChanged('abc', 'abc'), false);
});

test('a newer observed revision shows a notice without replacing loaded data', () => {
  assert.equal(revisionChanged('abc', 'def'), true);
});

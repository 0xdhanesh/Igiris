import test from 'node:test';
import assert from 'node:assert/strict';
import {baselineBoundary,parentsPath} from './dashboard.js';

test('parent search path includes process query and current baseline view',()=>{
  assert.equal(parentsPath('curl child',false),'/api/parents?search=curl%20child&baseline_only=false');
  assert.equal(parentsPath('203.0.113.77',true),'/api/parents?search=203.0.113.77&baseline_only=true');
});

test('baseline boundary is the newest entry currently displayed',()=>{
  const rows=[
    {last_activity:'2026-07-17T12:00:00+00:00'},
    {last_activity:'2026-07-17T12:05:00+00:00'},
    {last_activity:'2026-07-17T12:03:00+00:00'},
  ];
  assert.equal(baselineBoundary(rows),'2026-07-17T12:05:00+00:00');
  assert.equal(baselineBoundary([]),null);
});

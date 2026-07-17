import test from 'node:test';
import assert from 'node:assert/strict';
import { eventIdChanges, eventIdsAfterBoundary, eventRowUpdateClasses, historyCountChanges, parentEventBoundaryChanges, processPidsForEventIds } from './refresh-highlights.js';

const parent = (root_pid, history_event_count, latest_persistent_event_id = 0) => ({ root_pid, history_event_count, latest_persistent_event_id });

test('explicit refresh identifies only history counts that increased', () => {
  const changes = historyCountChanges(
    [parent(10, 4), parent(20, 9), parent(30, 3)],
    [parent(10, 6), parent(20, 9), parent(30, 2)],
  );
  assert.deepEqual(changes, { 10: 2 });
});

test('a newly appearing parent highlights its nonzero history count', () => {
  assert.deepEqual(
    historyCountChanges([parent(10, 4)], [parent(10, 4), parent(40, 3)]),
    { 40: 3 },
  );
});

test('initial loading does not highlight every parent', () => {
  assert.deepEqual(historyCountChanges(null, [parent(10, 4)]), {});
});

test('explicit refresh identifies only newly loaded event ids', () => {
  assert.deepEqual(
    eventIdChanges([{ id: 101 }, { id: 100 }], [{ id: 103 }, { id: 102 }, { id: 101 }]),
    [103, 102],
  );
});

test('initial event loading creates no event highlights', () => {
  assert.deepEqual(eventIdChanges(null, [{ id: 101 }]), []);
});

test('transient live socket rows without persistent ids are not highlighted as new history', () => {
  assert.deepEqual(eventIdChanges([{ id: 101 }], [{ id: null, type: 'live_socket' }, { id: 101 }]), []);
});

test('replaced live socket rows with new database ids are not highlighted as new history', () => {
  assert.deepEqual(
    eventIdChanges(
      [{ id: 101, type: 'connect' }, { id: 500, type: 'live_socket' }],
      [{ id: 501, type: 'live_socket' }, { id: 102, type: 'connect' }, { id: 101, type: 'connect' }],
    ),
    [102],
  );
});

test('new timeline event ids map to unique affected process tree rows', () => {
  const events = [
    { id: 105, pid: 41 },
    { id: 104, pid: 42 },
    { id: 103, pid: 41 },
    { id: 102, pid: 99 },
  ];
  assert.deepEqual(processPidsForEventIds(events, [105, 104, 103]), [41, 42]);
});

test('missing, transient, and unknown event ids do not highlight process rows', () => {
  assert.deepEqual(
    processPidsForEventIds([{ id: null, pid: 41 }, { id: 101, pid: 42 }], [null, 999]),
    [],
  );
});

test('main-page refresh preserves the previous event boundary for changed parents', () => {
  assert.deepEqual(
    parentEventBoundaryChanges(
      [parent(10, 4, 104), parent(20, 9, 209)],
      [parent(10, 6, 108), parent(20, 9, 209)],
    ),
    { 10: 104 },
  );
});

test('opening a changed parent later highlights only persistent events after its saved boundary', () => {
  assert.deepEqual(
    eventIdsAfterBoundary([
      { id: 110, type: 'live_socket' },
      { id: 109, type: 'connect' },
      { id: 108, type: 'dns' },
      { id: 104, type: 'connect' },
    ], 104),
    [109, 108],
  );
});

test('timeline row update classes are applied only to refreshed event ids', () => {
  assert.deepEqual(
    eventRowUpdateClasses(
      [{ id: 103 }, { id: 102 }, { id: 101 }],
      { 103: true },
    ),
    ['updated', '', ''],
  );
});

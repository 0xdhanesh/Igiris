import test from 'node:test';
import assert from 'node:assert/strict';
import { eventActor, mobilePanelClass, processDepth, processEventsPath, processSubtreeEvents, processSubtreeEventCount } from './timeline.js';

test('timeline event is attributed to its process name and pid', () => {
  assert.deepEqual(eventActor({ pid: 79793 }, [{ pid: 79793, name: 'python3' }]), {
    name: 'python3',
    pid: 79793,
    label: 'python3 · PID 79793',
  });
});

test('selected process query requests its complete root-scoped evidence', () => {
  assert.equal(
    processEventsPath(53784, 79793, false),
    '/api/events?root_pid=53784&pid=79793&include_descendants=true&baseline_only=false&mode=combined&limit=2000',
  );
});

test('process depth follows the persisted parent lineage', () => {
  const processes = [
    { pid: 10, ppid: 1, root_pid: 10 },
    { pid: 20, ppid: 10, root_pid: 10 },
    { pid: 30, ppid: 20, root_pid: 10 },
  ];
  assert.equal(processDepth(processes[0], processes), 0);
  assert.equal(processDepth(processes[1], processes), 1);
  assert.equal(processDepth(processes[2], processes), 2);
});

test('process activity count includes descendant network events', () => {
  const processes = [
    { pid: 10, ppid: 1, root_pid: 10 },
    { pid: 20, ppid: 10, root_pid: 10 },
    { pid: 30, ppid: 20, root_pid: 10 },
  ];
  const events = [{ pid: 30 }, { pid: 30 }, { pid: 99 }];
  assert.equal(processSubtreeEventCount(processes[0], processes, events), 2);
  assert.equal(processSubtreeEventCount(processes[1], processes, events), 2);
  assert.equal(processSubtreeEventCount(processes[2], processes, events), 2);
  assert.deepEqual(processSubtreeEvents(processes[1], processes, events), [{ pid: 30 }, { pid: 30 }]);
});

test('mobile panel classes keep the selected panel visible', () => {
  assert.equal(mobilePanelClass('tree', 'tree'), 'panel tree');
  assert.equal(mobilePanelClass('timeline', 'tree'), 'panel timeline mobile-hidden');
  assert.equal(mobilePanelClass('tree', 'timeline'), 'panel tree mobile-hidden');
  assert.equal(mobilePanelClass('timeline', 'timeline'), 'panel timeline');
});

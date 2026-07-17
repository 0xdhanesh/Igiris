import test from 'node:test';
import assert from 'node:assert/strict';
import { eventActor, mobilePanelClass, processEventsPath } from './timeline.js';

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
    '/api/events?root_pid=53784&pid=79793&baseline_only=false&mode=combined&limit=2000',
  );
});

test('mobile panel classes keep the selected panel visible', () => {
  assert.equal(mobilePanelClass('tree', 'tree'), 'panel tree');
  assert.equal(mobilePanelClass('timeline', 'tree'), 'panel timeline mobile-hidden');
  assert.equal(mobilePanelClass('tree', 'timeline'), 'panel tree mobile-hidden');
  assert.equal(mobilePanelClass('timeline', 'timeline'), 'panel timeline');
});

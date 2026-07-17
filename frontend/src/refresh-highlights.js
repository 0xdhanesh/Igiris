export function historyCountChanges(previousRows, nextRows) {
  if (!previousRows) return {};
  const previous = new Map(previousRows.map((row) => [row.root_pid, row.history_event_count]));
  return Object.fromEntries(
    nextRows.flatMap((row) => {
      const before = previous.get(row.root_pid) ?? 0;
      const increase = row.history_event_count - before;
      return increase > 0 ? [[row.root_pid, increase]] : [];
    }),
  );
}

export function eventIdChanges(previousEvents, nextEvents) {
  if (!previousEvents) return [];
  const previousIds = new Set(previousEvents.map((event) => event.id).filter(Boolean));
  return nextEvents
    .filter((event) => event.type !== 'live_socket')
    .map((event) => event.id)
    .filter((id) => id && !previousIds.has(id));
}

export function processPidsForEventIds(events, updatedEventIds) {
  const updated = new Set((updatedEventIds || []).filter(id => id !== null && id !== undefined));
  return [...new Set((events || []).filter(event => event.id !== null && event.id !== undefined && updated.has(event.id) && Number.isInteger(event.pid)).map(event => event.pid))];
}

export function parentEventBoundaryChanges(previousRows, nextRows) {
  if (!previousRows?.length) return {};
  const previous = new Map(previousRows.map(row => [row.root_pid, row]));
  return Object.fromEntries((nextRows || []).flatMap(row => {
    const before = previous.get(row.root_pid);
    return before && Number(row.history_event_count || 0) > Number(before.history_event_count || 0)
      ? [[row.root_pid, Number(before.latest_persistent_event_id || 0)]] : [];
  }));
}

export function eventIdsAfterBoundary(events, boundary) {
  const after = Number(boundary || 0);
  return (events || []).filter(event => event.type !== 'live_socket' && Number.isInteger(event.id) && event.id > after).map(event => event.id);
}

export function eventRowUpdateClasses(events, updatedEventIds) {
  const updated = updatedEventIds || {};
  return (events || []).map(event => event.id !== null && event.id !== undefined && updated[event.id] ? 'updated' : '');
}

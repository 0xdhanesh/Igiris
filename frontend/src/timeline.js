export function eventActor(event, processes) {
  const process = processes.find((item) => item.pid === event.pid);
  const name = process?.name || 'unknown process';
  return { name, pid: event.pid, label: `${name} · PID ${event.pid}` };
}

export function processDepth(process, processes) {
  const byPid = new Map(processes.map((item) => [item.pid, item]));
  let current = process;
  let depth = 0;
  const seen = new Set();
  while (current && current.pid !== current.root_pid && !seen.has(current.pid)) {
    seen.add(current.pid);
    current = byPid.get(current.ppid);
    if (current) depth += 1;
  }
  return depth;
}

export function processSubtreeEvents(process, processes, events) {
  const children = new Map();
  for (const item of processes) {
    const siblings = children.get(item.ppid) || [];
    siblings.push(item.pid);
    children.set(item.ppid, siblings);
  }
  const subtree = new Set();
  const queue = [process.pid];
  while (queue.length) {
    const pid = queue.shift();
    if (subtree.has(pid)) continue;
    subtree.add(pid);
    queue.push(...(children.get(pid) || []));
  }
  return events.filter((event) => subtree.has(event.pid));
}

export function processSubtreeEventCount(process, processes, events) {
  return processSubtreeEvents(process, processes, events).length;
}

export function processEventsPath(rootPid, pid, baselineOnly) {
  const params = new URLSearchParams({
    root_pid: String(rootPid),
    pid: String(pid),
    include_descendants: 'true',
    baseline_only: String(baselineOnly),
    mode: 'combined',
    limit: '2000',
  });
  return `/api/events?${params}`;
}

export function mobilePanelClass(kind, active) {
  return `panel ${kind}${kind === active ? '' : ' mobile-hidden'}`;
}

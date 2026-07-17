export function eventActor(event, processes) {
  const process = processes.find((item) => item.pid === event.pid);
  const name = process?.name || 'unknown process';
  return { name, pid: event.pid, label: `${name} · PID ${event.pid}` };
}

export function processEventsPath(rootPid, pid, baselineOnly) {
  const params = new URLSearchParams({
    root_pid: String(rootPid),
    pid: String(pid),
    baseline_only: String(baselineOnly),
    mode: 'combined',
    limit: '2000',
  });
  return `/api/events?${params}`;
}

export function mobilePanelClass(kind, active) {
  return `panel ${kind}${kind === active ? '' : ' mobile-hidden'}`;
}

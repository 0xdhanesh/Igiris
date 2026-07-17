export async function loginWithPassword(password, fetchImpl = fetch) {
  const response = await fetchImpl('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }),
    cache: 'no-store',
  });
  if (!response.ok) {
    let detail = response.status === 429
      ? 'Too many failed login attempts. Try again later.'
      : 'Unable to unlock Igiris.';
    try {
      const body = await response.json();
      if (body?.detail) detail = body.detail;
    } catch {
      // Keep the safe status-based message.
    }
    throw new Error(detail);
  }
  return response.json();
}

export function sessionHeaders(token) {
  return token ? { Authorization: 'Bearer ' + token } : {};
}

export function handleAuthRequired(error, onAuthRequired) {
  if (error?.code !== 'AUTH_REQUIRED') return false;
  onAuthRequired();
  return true;
}

import assert from 'node:assert/strict';
import test from 'node:test';

import { handleAuthRequired, loginWithPassword, sessionHeaders } from './auth.js';


test('password login exchanges the password for a session without reusing it as bearer auth', async () => {
  let request;
  const session = await loginWithPassword('private password', async (path, options) => {
    request = { path, options };
    return {
      ok: true,
      json: async () => ({ token: 'random-session-token', expires_in: 300 }),
    };
  });

  assert.equal(request.path, '/api/auth/login');
  assert.equal(request.options.method, 'POST');
  assert.deepEqual(JSON.parse(request.options.body), { password: 'private password' });
  assert.equal(request.options.headers['Content-Type'], 'application/json');
  assert.deepEqual(session, { token: 'random-session-token', expires_in: 300 });
  assert.deepEqual(sessionHeaders(session.token), { Authorization: 'Bearer random-session-token' });
  assert.notEqual(session.token, 'private password');
});


test('password login surfaces an invalid-password response', async () => {
  await assert.rejects(
    loginWithPassword('wrong', async () => ({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Invalid password' }),
    })),
    /Invalid password/,
  );
});


test('AUTH_REQUIRED handling centrally invokes the unlock transition', () => {
  let transitions = 0;
  const authError = Object.assign(new Error('AUTH_REQUIRED'), { code: 'AUTH_REQUIRED' });

  assert.equal(handleAuthRequired(authError, () => { transitions += 1; }), true);
  assert.equal(handleAuthRequired(new Error('network failed'), () => { transitions += 1; }), false);
  assert.equal(transitions, 1);
});

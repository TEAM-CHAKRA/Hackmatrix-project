import test from 'node:test';
import assert from 'node:assert/strict';
import request from 'supertest';
import app from '../src/app.js';
import { beginStartup, finishStartup } from '../src/middleware/startupGate.js';

test('Startup gate: liveness answers at once; API requests wait for startup, then go through', async () => {
  beginStartup();
  try {
    const live = await request(app).get('/api/health/live');
    assert.equal(live.status, 200, 'liveness must not wait');
    const ready = await request(app).get('/api/health/ready');
    assert.equal(ready.status, 503);
    assert.equal(ready.body.checks.startup, 'unavailable');

    const pending = request(app).get('/api/auth/me');
    setTimeout(finishStartup, 300);
    const t0 = Date.now();
    const res = await pending;
    assert.ok(Date.now() - t0 >= 250, 'request waited for startup');
    assert.equal(res.status, 401, 'then handled normally');
  } finally {
    finishStartup();
  }
});

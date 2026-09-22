import 'reflect-metadata';
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { Controller, Get, Module, Post } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter } from '@nestjs/platform-fastify';
import { assertLiveness } from '@sda/testing';
import { AppModule } from '../../dist/app.module.js';
import { createApplication } from '../../dist/application.js';

let application;
const dependencyEnvironment = {
  DATABASE_URL: process.env.DATABASE_URL,
  REDIS_URL: process.env.REDIS_URL,
  STORAGE_ENDPOINT: process.env.STORAGE_ENDPOINT,
  STORAGE_PORT: process.env.STORAGE_PORT,
};

before(async () => {
  process.env.DATABASE_URL = 'postgresql://127.0.0.1:1/isolated_health_test';
  process.env.REDIS_URL = 'redis://127.0.0.1:1/0';
  process.env.STORAGE_ENDPOINT = '127.0.0.1';
  process.env.STORAGE_PORT = '1';
  application = await createApplication();
  await application.init();
  await application.getHttpAdapter().getInstance().ready();
});
after(async () => {
  await application?.close();
  for (const [name, value] of Object.entries(dependencyEnvironment)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
});

test('public liveness responds with the shared contract and no cache', async () => {
  const response = await application.inject({ method: 'GET', url: '/api/v1/health/live' });
  assert.equal(response.statusCode, 200);
  assertLiveness(response.json());
  assert.equal(response.headers['cache-control'], 'no-store');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
});

test('readiness is public, degraded when required local dependencies are absent, and redacted', async () => {
  const response = await application.inject({ method: 'GET', url: '/api/v1/health/ready' });
  assert.equal(response.statusCode, 503);
  assert.equal(response.json().status, 'degraded');
  assert.deepEqual(Object.keys(response.json().checks), ['database', 'redis', 'storage']);
  assert.equal(response.json().stack, undefined);
  assert.doesNotMatch(response.body, /password|secret|credential|postgresql:\/\//i);
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('business endpoints remain unavailable', async () => {
  const response = await application.inject({ method: 'GET', url: '/api/v1/documents' });
  assert.equal(response.statusCode, 404);
  assert.equal(response.json().stack, undefined);
});

test('RBAC administration endpoint returns 401 without authentication', async () => {
  const response = await application.inject({ method: 'GET', url: '/api/v1/users' });
  assert.equal(response.statusCode, 401);
  assert.equal(response.json().errorCode, 'UNAUTHORIZED');
});

test('global guard denies an undecorated route even with forged frontend attributes', async () => {
  class ProtectedFixtureController {
    probe() {
      return { shouldNeverBeDisclosed: true };
    }
  }
  Controller('protected-fixture')(ProtectedFixtureController);
  const descriptor = Object.getOwnPropertyDescriptor(ProtectedFixtureController.prototype, 'probe');
  Get()(ProtectedFixtureController.prototype, 'probe', descriptor);
  class ProtectedPostFixtureController {
    probe() {
      return { shouldNeverBeDisclosed: true };
    }
  }
  Controller('protected-post-fixture')(ProtectedPostFixtureController);
  Post()(
    ProtectedPostFixtureController.prototype,
    'probe',
    Object.getOwnPropertyDescriptor(ProtectedPostFixtureController.prototype, 'probe'),
  );
  class FixtureModule {}
  Module({
    imports: [AppModule],
    controllers: [ProtectedFixtureController, ProtectedPostFixtureController],
  })(FixtureModule);
  const fixture = await NestFactory.create(FixtureModule, new FastifyAdapter({ logger: false }), {
    logger: false,
    abortOnError: false,
  });
  try {
    fixture.setGlobalPrefix('api/v1');
    await fixture.init();
    await fixture.getHttpAdapter().getInstance().ready();
    for (const request of [
      { method: 'GET', url: '/api/v1/protected-fixture' },
      {
        method: 'GET',
        url: '/api/v1/protected-fixture?role=ADMIN&clearance=999&department=SECURITY',
        headers: { 'x-role': 'ADMIN', 'x-clearance': '999', 'x-department': 'SECURITY' },
      },
      {
        method: 'POST',
        url: '/api/v1/protected-post-fixture',
        payload: { role: 'ADMIN', clearance: 999, department: 'SECURITY' },
      },
    ]) {
      const response = await fixture.inject(request);
      assert.equal(response.statusCode, 401);
      assert.equal(response.json().shouldNeverBeDisclosed, undefined);
      assert.equal(response.json().stack, undefined);
    }
  } finally {
    await fixture.close();
  }
});

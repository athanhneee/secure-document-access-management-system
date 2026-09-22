import 'reflect-metadata';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Reflector } from '@nestjs/core';
import { DefaultDenyGuard } from '../dist/default-deny.guard.js';
import { PUBLIC_ENDPOINT_METADATA } from '../dist/public-endpoint.js';

const guard = new DefaultDenyGuard(new Reflector());

function contextFor(handler) {
  return { getHandler: () => handler };
}

test('routes without explicit server metadata are denied', () => {
  const handler = () => 'protected';
  assert.equal(guard.canActivate(contextFor(handler)), false);
});

test('only strict true metadata permits a deliberately public handler', () => {
  const handler = () => 'public';
  for (const declaration of [false, 'true', { role: 'ADMIN' }, undefined]) {
    Reflect.defineMetadata(PUBLIC_ENDPOINT_METADATA, declaration, handler);
    assert.equal(guard.canActivate(contextFor(handler)), false);
  }
  Reflect.defineMetadata(PUBLIC_ENDPOINT_METADATA, true, handler);
  assert.equal(guard.canActivate(contextFor(handler)), true);
});

test('the guard never trusts identity attributes supplied by the frontend', () => {
  const handler = () => 'protected';
  const context = {
    getHandler: () => handler,
    switchToHttp: () => {
      throw new Error('Untrusted request identity must not be read by the bootstrap guard.');
    },
    role: 'ADMIN',
    clearance: 999,
    department: 'SECURITY',
  };
  assert.equal(guard.canActivate(context), false);
});

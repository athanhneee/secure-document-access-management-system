import assert from 'node:assert/strict';
import test from 'node:test';
import { isAssignmentActive } from '../dist/modules/abac/assignment-validity.js';
import { cidrMatch, evaluatePolicy } from '../dist/modules/abac/policy-engine.js';
import { baseInput, policy, rule } from './helpers/abac-test-fixtures.mjs';

test('time windows are timezone-aware, inclusive at boundaries, and support overnight', () => {
  const daytime = rule(1, [
    {
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '09:00:00', end: '17:00:00', timeZone: 'Asia/Ho_Chi_Minh' },
    },
  ]);
  for (const currentTime of ['2026-01-01T02:00:00.000Z', '2026-01-01T10:00:00.000Z']) {
    const input = structuredClone(baseInput);
    input.environment.currentTime = currentTime;
    assert.equal(evaluatePolicy(policy([daytime]), input).decision, 'PERMIT');
  }
  const outside = structuredClone(baseInput);
  outside.environment.currentTime = '2026-01-01T10:00:01.000Z';
  assert.equal(evaluatePolicy(policy([daytime]), outside).decision, 'DENY');
  const overnight = rule(2, [
    {
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '22:00', end: '06:00', timeZone: 'UTC' },
    },
  ]);
  const late = structuredClone(baseInput);
  late.environment.currentTime = '2026-01-01T23:30:00.000Z';
  assert.equal(evaluatePolicy(policy([overnight]), late).decision, 'PERMIT');
});

test('TIME_BETWEEN midnight wrap handles 23:00 to 01:00 correctly', () => {
  const overnight = rule(1, [
    {
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '23:00', end: '01:00', timeZone: 'UTC' },
    },
  ]);
  const at2330 = structuredClone(baseInput);
  at2330.environment.currentTime = '2026-06-15T23:30:00.000Z';
  assert.equal(evaluatePolicy(policy([overnight]), at2330).decision, 'PERMIT');

  const at0030 = structuredClone(baseInput);
  at0030.environment.currentTime = '2026-06-15T00:30:00.000Z';
  assert.equal(evaluatePolicy(policy([overnight]), at0030).decision, 'PERMIT');

  const at0200 = structuredClone(baseInput);
  at0200.environment.currentTime = '2026-06-15T02:00:00.000Z';
  assert.equal(evaluatePolicy(policy([overnight]), at0200).decision, 'DENY');
});

test('TIME_BETWEEN full day range 00:00:00 to 23:59:59 permits at boundaries', () => {
  const allDay = rule(1, [
    {
      attribute: 'environment.currentTime',
      operator: 'TIME_BETWEEN',
      expected: { start: '00:00:00', end: '23:59:59', timeZone: 'UTC' },
    },
  ]);
  const atMidnight = structuredClone(baseInput);
  atMidnight.environment.currentTime = '2026-06-15T00:00:00.000Z';
  assert.equal(evaluatePolicy(policy([allDay]), atMidnight).decision, 'PERMIT');

  const atEnd = structuredClone(baseInput);
  atEnd.environment.currentTime = '2026-06-15T23:59:59.000Z';
  assert.equal(evaluatePolicy(policy([allDay]), atEnd).decision, 'PERMIT');
});

test('CIDR matching handles IPv4 and compressed IPv6 boundaries', () => {
  assert.equal(cidrMatch('10.255.255.255', '10.0.0.0/8'), true);
  assert.equal(cidrMatch('11.0.0.0', '10.0.0.0/8'), false);
  assert.equal(cidrMatch('2001:db8:ffff::1', '2001:db8::/32'), true);
  assert.equal(cidrMatch('2001:db9::1', '2001:db8::/32'), false);
  assert.equal(cidrMatch('::ffff:192.0.2.1', '::ffff:192.0.2.0/120'), true);
});

test('CIDR /0 matches any IPv4 and /32 matches exact IPv4 only', () => {
  assert.equal(cidrMatch('192.168.1.1', '0.0.0.0/0'), true);
  assert.equal(cidrMatch('255.255.255.255', '0.0.0.0/0'), true);
  assert.equal(cidrMatch('10.20.30.40', '10.20.30.40/32'), true);
  assert.equal(cidrMatch('10.20.30.41', '10.20.30.40/32'), false);
});

test('CIDR /128 matches exact IPv6 only', () => {
  assert.equal(cidrMatch('2001:db8::1', '2001:db8::1/128'), true);
  assert.equal(cidrMatch('2001:db8::2', '2001:db8::1/128'), false);
  assert.equal(cidrMatch('::1', '::1/128'), true);
  assert.equal(cidrMatch('::2', '::1/128'), false);
});

test('CIDR without prefix length matches exact address', () => {
  assert.equal(cidrMatch('10.20.30.40', '10.20.30.40'), true);
  assert.equal(cidrMatch('10.20.30.41', '10.20.30.40'), false);
});

test('expired assignments are inactive at the exact valid_to boundary', () => {
  const at = new Date('2026-01-01T00:00:00.000Z');
  assert.equal(
    isAssignmentActive(
      {
        validFrom: new Date('2025-01-01T00:00:00.000Z'),
        validTo: new Date('2026-01-01T00:00:00.000Z'),
      },
      at,
    ),
    false,
  );
  assert.equal(
    isAssignmentActive({ validFrom: new Date('2026-01-01T00:00:00.000Z'), validTo: null }, at),
    true,
  );
});

test('rule at exact valid_to timestamp is not matched', () => {
  const expiredRule = rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }], {
    validFrom: '2020-01-01T00:00:00.000Z',
    validTo: '2026-01-01T02:00:00.000Z',
  });
  const input = structuredClone(baseInput);
  input.environment.currentTime = '2026-01-01T02:00:00.000Z';
  const result = evaluatePolicy(policy([expiredRule]), input);
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'DEFAULT_DENY');
  assert.deepEqual(result.matchedRuleIds, []);
});

test('rule not yet valid (currentTime before validFrom) is not matched', () => {
  const futureRule = rule(1, [{ attribute: 'environment.mfa', operator: 'EQ', expected: true }], {
    validFrom: '2030-01-01T00:00:00.000Z',
    validTo: null,
  });
  const result = evaluatePolicy(policy([futureRule]), baseInput);
  assert.equal(result.decision, 'DENY');
  assert.equal(result.reasonCode, 'DEFAULT_DENY');
});

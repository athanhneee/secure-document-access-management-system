import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, it } from 'node:test';

const ROOT = resolve(import.meta.dirname, '../..');
const WEB_ROOT = resolve(ROOT, 'apps/web');

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('@/')) {
      const target = resolve(WEB_ROOT, `${specifier.slice(2)}.ts`);
      return nextResolve(pathToFileURL(target).href, context);
    }
    try {
      return nextResolve(specifier, context);
    } catch (error) {
      if (specifier.startsWith('./') || specifier.startsWith('../')) {
        return nextResolve(`${specifier}.ts`, context);
      }
      throw error;
    }
  },
});

const {
  DEFAULT_INITIAL_RULE,
  DEFAULT_SESSION_MINUTES,
  MAX_SESSION_MINUTES,
  MIN_SESSION_MINUTES,
  clampSessionMinutes,
  deserializePolicyAst,
  normalizeSessionMinutesDraftOnBlur,
  parseSessionMinutesDraft,
  serializePolicyAst,
  validateVisualPolicyRule,
} = await import('../../apps/web/components/abac/policy-ast-helpers.ts');
const { normalizeVisualObligations } = await import('../../apps/web/app/admin/abac-helpers.ts');

describe('BUG-040: ABAC Builder JSON Mode synchronization & validation', () => {
  it('deserializes valid edited JSON AST preserving metadata, conditions, and obligations', () => {
    const edited = {
      ...DEFAULT_INITIAL_RULE,
      code: 'POL_FINANCE_STRICT_JSON',
      name: 'Chính sách tài chính chỉnh từ JSON nâng cao',
      effect: 'DENY',
      priority: 5,
      targetAction: 'DOWNLOAD',
      obligations: [{ type: 'MAX_SESSION_MINUTES', minutes: 90 }, 'NO_CACHE'],
    };

    const parsed = deserializePolicyAst(JSON.stringify(edited, null, 2));
    assert.equal(parsed.code, 'POL_FINANCE_STRICT_JSON');
    assert.equal(parsed.name, 'Chính sách tài chính chỉnh từ JSON nâng cao');
    assert.equal(parsed.effect, 'DENY');
    assert.equal(parsed.priority, 5);
    assert.equal(parsed.targetAction, 'DOWNLOAD');
    assert.deepEqual(parsed.obligations, [
      { type: 'MAX_SESSION_MINUTES', minutes: 90 },
      { type: 'NO_CACHE' },
    ]);
  });

  it('rejects malformed JSON syntax and schema violations in deserializePolicyAst', () => {
    assert.throws(() => deserializePolicyAst('{ invalid json '), /Cú pháp JSON không hợp lệ/u);
    assert.throws(() => deserializePolicyAst('[]'), /đối tượng JSON/u);

    assert.throws(
      () => deserializePolicyAst(serializePolicyAst({ ...DEFAULT_INITIAL_RULE, code: 'A' })),
      /"code"/u,
    );

    assert.throws(
      () => deserializePolicyAst(JSON.stringify({ ...DEFAULT_INITIAL_RULE, effect: 'ALLOW' })),
      /"effect"/u,
    );

    assert.throws(
      () => deserializePolicyAst(JSON.stringify({ ...DEFAULT_INITIAL_RULE, groups: [] })),
      /"groups"/u,
    );

    assert.throws(
      () =>
        deserializePolicyAst(
          JSON.stringify({
            ...DEFAULT_INITIAL_RULE,
            groups: [{ id: 1, conditions: [] }],
          }),
        ),
      /nhóm điều kiện #1/u,
    );

    assert.throws(
      () =>
        deserializePolicyAst(
          JSON.stringify({
            ...DEFAULT_INITIAL_RULE,
            groups: [
              {
                id: 1,
                conditions: [
                  { id: 'c-1', attribute: 'subject.clearanceRank', operator: 'LIKE', expected: 2 },
                ],
              },
            ],
          }),
        ),
      /toán tử "LIKE"/u,
    );
  });

  it('enforces JSON-mode parse before Save / Simulate / Visual switch, hides PolicyMetaCard in JSON mode, and never reformats on keystroke', () => {
    const builderSrc = readFileSync(
      resolve(ROOT, 'apps/web/components/abac/visual-policy-builder.tsx'),
      'utf8',
    );
    const presetsBarSrc = readFileSync(
      resolve(ROOT, 'apps/web/components/abac/policy-presets-bar.tsx'),
      'utf8',
    );

    // PolicyMetaCard must be hidden when viewMode === 'json' to prevent cross-overwriting jsonText
    assert.match(
      presetsBarSrc,
      /\{viewMode === 'visual' && <PolicyMetaCard rule=\{rule\} onUpdateRule=\{onUpdateRule\} \/>\}/u,
    );

    // Save, Simulator, and ViewMode switch all route through resolveRuleForSubmission()
    assert.match(builderSrc, /const resolveRuleForSubmission = \(\): VisualPolicyRule \| null =>/u);
    assert.match(builderSrc, /deserializePolicyAst\(jsonText\)/u);
    assert.match(builderSrc, /await onSaveRule\(resolved\)/u);

    // Never call serializePolicyAst or deserializePolicyAst inside onChangeJsonText handler
    const onChangeMatch = builderSrc.match(/onChangeJsonText=\{\(nextText\) => \{([\s\S]*?)\}\}/u);
    assert.ok(onChangeMatch, 'Expected inline onChangeJsonText handler');
    assert.doesNotMatch(onChangeMatch[1], /deserializePolicyAst|serializePolicyAst|JSON\.parse/u);
  });
});

describe('BUG-041: ABAC Obligations MAX_SESSION_MINUTES draft input & [1, 1440] bounds', () => {
  it('allows empty draft while typing, strips leading zeros on blur, and clamps into [1, 1440]', () => {
    assert.equal(MIN_SESSION_MINUTES, 1);
    assert.equal(MAX_SESSION_MINUTES, 1440);
    assert.equal(DEFAULT_SESSION_MINUTES, 30);

    // Empty string while user presses Backspace: invalid for direct save, restores fallback on blur
    const emptyDraft = parseSessionMinutesDraft('');
    assert.equal(emptyDraft.valid, false);
    assert.equal(normalizeSessionMinutesDraftOnBlur('', 30), 30);
    assert.equal(normalizeSessionMinutesDraftOnBlur('   ', 45), 45);

    // Leading zeros ("015") parse to 15 and normalize cleanly to 15 on blur
    const leadingZeroDraft = parseSessionMinutesDraft('015');
    assert.deepEqual(leadingZeroDraft, { valid: true, minutes: 15 });
    assert.equal(normalizeSessionMinutesDraftOnBlur('015', 30), 15);

    // Out-of-bounds values ("0", "-5", "2000", "12.5") rejected by strict parser & clamped on blur
    assert.equal(parseSessionMinutesDraft('0').valid, false);
    assert.equal(parseSessionMinutesDraft('-5').valid, false);
    assert.equal(parseSessionMinutesDraft('1441').valid, false);
    assert.equal(parseSessionMinutesDraft('12.5').valid, false);

    assert.equal(normalizeSessionMinutesDraftOnBlur('0', 30), 1);
    assert.equal(normalizeSessionMinutesDraftOnBlur('-20', 30), 1);
    assert.equal(normalizeSessionMinutesDraftOnBlur('5000', 30), 1440);
    assert.equal(clampSessionMinutes(0), 1);
    assert.equal(clampSessionMinutes(9999), 1440);

    // Boundary values 1 and 1440 are accepted
    assert.deepEqual(parseSessionMinutesDraft('1'), { valid: true, minutes: 1 });
    assert.deepEqual(parseSessionMinutesDraft('1440'), { valid: true, minutes: 1440 });
  });

  it('strictly validates MAX_SESSION_MINUTES in both validateVisualPolicyRule and deserializePolicyAst', () => {
    const validRule = {
      ...DEFAULT_INITIAL_RULE,
      obligations: [{ type: 'MAX_SESSION_MINUTES', minutes: 1440 }],
    };
    assert.equal(validateVisualPolicyRule(validRule), null);

    const zeroRule = {
      ...DEFAULT_INITIAL_RULE,
      obligations: [{ type: 'MAX_SESSION_MINUTES', minutes: 0 }],
    };
    assert.match(validateVisualPolicyRule(zeroRule) ?? '', /1 đến 1440/u);

    const overMaxRule = {
      ...DEFAULT_INITIAL_RULE,
      obligations: [{ type: 'MAX_SESSION_MINUTES', minutes: 1441 }],
    };
    assert.match(validateVisualPolicyRule(overMaxRule) ?? '', /1 đến 1440/u);

    assert.throws(
      () => deserializePolicyAst(JSON.stringify(zeroRule)),
      /MAX_SESSION_MINUTES.*1 đến 1440/u,
    );
    assert.throws(
      () => deserializePolicyAst(JSON.stringify(overMaxRule)),
      /MAX_SESSION_MINUTES.*1 đến 1440/u,
    );

    assert.deepEqual(normalizeVisualObligations([{ type: 'MAX_SESSION_MINUTES', minutes: 9999 }]), [
      { type: 'MAX_SESSION_MINUTES', minutes: 1440 },
    ]);
  });

  it('uses local draftMinutes state and [1, 1440] HTML attributes in ObligationsPanel without || 30 snap-back', () => {
    const obligationsSrc = readFileSync(
      resolve(ROOT, 'apps/web/components/abac/obligations-panel.tsx'),
      'utf8',
    );

    assert.match(obligationsSrc, /const \[draftMinutes, setDraftMinutes\] = useState<string>/u);
    assert.match(obligationsSrc, /min=\{MIN_SESSION_MINUTES\}/u);
    assert.match(obligationsSrc, /max=\{MAX_SESSION_MINUTES\}/u);
    assert.match(obligationsSrc, /onBlur=\{\(\) =>/u);
    assert.doesNotMatch(obligationsSrc, /\?\.minutes \|\| 30/u);
    assert.doesNotMatch(obligationsSrc, /min="5"/u);
    assert.doesNotMatch(obligationsSrc, /max="240"/u);
  });
});

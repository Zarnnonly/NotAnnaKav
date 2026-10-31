const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

function app(backend = async () => ({ scanned: 1, signatures: 10, skipped: 0, findings: [], warnings: [] })) {
  const elements = new Map();
  const element = () => ({
    value: '', checked: false, disabled: false, hidden: false, textContent: '',
    events: {}, children: [], classList: { add() {}, remove() {} },
    addEventListener(name, callback) { this.events[name] = callback; },
    replaceChildren() { this.children = []; }, append(...children) { this.children.push(...children); },
  });
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const calls = [];
  const context = vm.createContext({
    document: { getElementById: get, createElement: element },
    window: { __TAURI__: { core: { Channel: class {}, invoke: async (name, args) => {
      calls.push({ name, args });
      return backend(name, args);
    } } } },
  });
  vm.runInContext(readFileSync(require.resolve('../ui/app.js'), 'utf8'), context);
  return { get, calls };
}

test('a target alone starts a bundled scan and keeps custom controls disabled afterward', async () => {
  const { get, calls } = app();
  assert.equal(get('custom-database-fields').hidden, true);
  assert.equal(get('database').disabled, true);
  get('target').value = 'C:/samples';
  get('database').value = 'stale custom path';
  await get('scan').events.click();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].name, 'scan_folder');
  assert.equal(calls[0].args.database, null);
  assert.equal(get('export').disabled, false);
  assert.equal(get('database').disabled, true);
  assert.equal(get('choose-database').disabled, true);
});

test('progress is live, Stop targets this scan, partial findings remain exportable, and stale updates are ignored', async () => {
  let finish;
  const finding = {
    signature: '<script>label</script>', path: 'C:/samples/test.exe', sha256: 'a'.repeat(64),
    size_bytes: 100, signature_source: 'Included database',
    detection_method: 'Exact SHA-256 match', reason: 'The digests match.',
  };
  const { get, calls } = app((name) => name === 'stop_scan' ? true : new Promise((resolve) => { finish = resolve; }));
  get('target').value = 'C:/samples';
  const running = get('scan').events.click();
  assert.equal(get('scan').disabled, true);
  const args = calls[0].args;
  const progress = { phase: 'scanning', scanned: 2, signatures: 10, matches: 1, skipped: 0,
    current_file: finding.path, file_bytes: 100, file_size: 100, elapsed_ms: 1200, finding };
  args.onProgress.onmessage(progress);
  assert.equal(get('scanned').textContent, '2');
  assert.match(get('current-file').textContent, /test.exe/);
  assert.match(get('progress-summary').textContent, /1.2s/);
  assert.equal(get('stop').disabled, false);
  assert.equal(get('findings').children.length, 1);
  const card = get('findings').children[0];
  assert.match(card.children[0].textContent, /<script>label<\/script>/);
  const fields = card.children[2].children[1].children;
  assert.ok(fields.some((field) => field.textContent === 'Included database'));
  assert.ok(fields.some((field) => field.textContent === 'Exact SHA-256 match'));
  await get('scan').events.click();
  assert.equal(calls.length, 1);
  await get('stop').events.click();
  assert.equal(calls[1].name, 'stop_scan');
  assert.equal(calls[1].args.scanId, args.scanId);
  assert.equal(get('stop').disabled, true);
  args.onProgress.onmessage({ ...progress, finding: null });
  assert.equal(get('stop').disabled, true);
  finish({ scanned: 2, signatures: 10, skipped: 0, findings: [finding], warnings: [], stopped: true, elapsed_ms: 1400 });
  await running;
  assert.match(get('status').textContent, /results are partial/);
  assert.equal(get('export').disabled, false);
  assert.equal(get('findings').children.length, 1);
  assert.equal(get('scan').disabled, false);
  args.onProgress.onmessage({ ...progress, scanned: 99 });
  assert.equal(get('scanned').textContent, '2');
});

test('failed stop can be retried without losing the running inspection', async () => {
  let finish;
  const { get, calls } = app((name) => {
    if (name === 'stop_scan') throw new Error('IPC failure');
    return new Promise((resolve) => { finish = resolve; });
  });
  get('target').value = 'C:/samples';
  const running = get('scan').events.click();
  calls[0].args.onProgress.onmessage({ phase: 'scanning', scanned: 0, signatures: 10, matches: 0, skipped: 0, elapsed_ms: 0 });
  await get('stop').events.click();
  assert.match(get('status').textContent, /Could not stop/);
  assert.equal(get('stop').disabled, false);
  finish({ scanned: 0, signatures: 10, skipped: 0, findings: [], warnings: [], stopped: false, elapsed_ms: 100 });
  await running;
  assert.equal(get('stop').disabled, true);
});

test('custom selection requires a path, then sends that exact database', async () => {
  const { get, calls } = app();
  get('target').value = 'C:/samples';
  get('custom-database').checked = true;
  get('custom-database').events.change();
  assert.equal(get('custom-database-fields').hidden, false);
  assert.equal(get('database').disabled, false);
  await get('scan').events.click();
  assert.equal(calls.length, 0);
  get('database').value = 'C:/signatures';
  await get('scan').events.click();
  assert.equal(calls[0].args.database, 'C:/signatures');
  assert.equal(get('database').disabled, false);
});

test('custom database failure reports an error without retrying against bundled records', async () => {
  const { get, calls } = app(async () => { throw new Error('Database unavailable'); });
  get('target').value = 'C:/samples';
  get('custom-database').checked = true;
  get('database').value = 'C:/missing';
  await get('scan').events.click();
  assert.equal(calls.length, 1);
  assert.match(get('status').textContent, /Database unavailable/);
  assert.equal(get('custom-database').checked, true);
  assert.equal(get('custom-database').disabled, false);
  assert.equal(get('export').disabled, true);
});

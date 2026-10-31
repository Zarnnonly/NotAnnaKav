const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

function app(backend = async () => ({ scanned: 1, signatures: 10, skipped: 0, findings: [], warnings: [] }), history = [], listHistory = () => ({ entries: history, warnings: [] })) {
  const elements = new Map();
  const element = () => ({
    value: '', checked: false, disabled: false, hidden: false, textContent: '',
    events: {}, children: [], classList: { add() {}, remove() {} },
    addEventListener(name, callback) { this.events[name] = callback; },
    click() {}, replaceChildren() { this.children = []; }, append(...children) { this.children.push(...children); },
  });
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const calls = [];
  let dropHandler;
  let exported;
  const context = vm.createContext({
    Blob, URL: { createObjectURL(blob) { exported = blob; return 'blob:test'; }, revokeObjectURL() {} },
    setTimeout(callback) { callback(); },
    document: { getElementById: get, createElement: element },
    window: { __TAURI__: { core: { Channel: class {}, invoke: async (name, args) => {
      if (name === 'list_history') return listHistory();
      calls.push({ name, args });
      return backend(name, args);
    } }, webview: { getCurrentWebview: () => ({ onDragDropEvent: async (handler) => { dropHandler = handler; } }) } } },
  });
  vm.runInContext(readFileSync(require.resolve('../ui/app.js'), 'utf8'), context);
  return { get, calls, drop: (payload) => dropHandler({ payload }), exported: () => exported };
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

test('file picker and native drops select one target without starting a scan', async () => {
  const { get, calls, drop } = app(async () => 'C:/samples/one.exe');
  await get('choose-file').events.click();
  assert.equal(calls[0].name, 'choose_file');
  assert.equal(get('target').value, 'C:/samples/one.exe');
  drop({ type: 'drop', paths: ['C:/folder'] });
  assert.equal(get('target').value, 'C:/folder');
  drop({ type: 'drop', paths: ['C:/one', 'C:/two'] });
  assert.equal(get('target').value, 'C:/folder');
  assert.match(get('drop-zone').textContent, /one file or folder/);
  assert.equal(calls.length, 1);
});

test('saved partial report can be reopened and exported after app startup', async () => {
  const saved = { id: '123-1', completed_at_ms: 1700000000000, target: 'C:/old/file.exe', database: 'bundled',
    scanned: 1, signatures: 10, skipped: 0, findings: [], warnings: ['Skipped something'], stopped: true, elapsed_ms: 25 };
  const { get, calls, exported } = app(async () => saved, [{ ...saved, matches: 0 }]);
  await get('refresh-history').events.click();
  const button = get('history-list').children[0].children[1];
  await button.events.click();
  assert.equal(calls[0].name, 'read_history');
  assert.equal(calls[0].args.id, saved.id);
  assert.match(get('report-context').textContent, /Saved inspection.*old\/file.exe/);
  assert.match(get('status').textContent, /partial/);
  assert.equal(get('warnings').textContent, 'Skipped something');
  assert.equal(get('export').disabled, false);
  get('export').events.click();
  const json = JSON.parse(await exported().text());
  assert.equal(json.id, saved.id);
  assert.equal(json.stopped, true);
});

test('history write failure keeps scan results exportable and shows the error', async () => {
  const { get } = app(async () => ({ scanned: 1, signatures: 10, skipped: 0, findings: [], warnings: [],
    history_error: 'Could not save scan history: disk full' }));
  get('target').value = 'C:/sample.txt';
  await get('scan').events.click();
  assert.match(get('status').textContent, /disk full/);
  assert.equal(get('export').disabled, false);
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
    current_file: finding.path, file_bytes: 100, file_size: 100, elapsed_ms: 1200, findings: [finding], finding_offset: 0 };
  args.onProgress.onmessage(progress);
  assert.equal(get('scanned').textContent, '2');
  assert.match(get('current-file').textContent, /test.exe/);
  assert.match(get('progress-summary').textContent, /1.2s/);
  assert.equal(get('stop').disabled, false);
  assert.equal(get('findings').children.length, 1);
  const card = get('findings').children[0];
  assert.match(card.children[0].textContent, /<script>label<\/script>/);
  assert.equal(card.children[2].children.length, 1, 'details are not built until expanded');
  card.children[2].open = true;
  card.children[2].events.toggle();
  const fields = card.children[2].children[1].children;
  assert.ok(fields.some((field) => field.textContent === 'Included database'));
  assert.ok(fields.some((field) => field.textContent === 'Exact SHA-256 match'));
  await get('scan').events.click();
  assert.equal(calls.length, 1);
  await get('stop').events.click();
  assert.equal(calls[1].name, 'stop_scan');
  assert.equal(calls[1].args.scanId, args.scanId);
  assert.equal(get('stop').disabled, true);
  args.onProgress.onmessage({ ...progress, findings: [] });
  assert.equal(get('stop').disabled, true);
  finish({ scanned: 2, signatures: 10, skipped: 0, findings: [finding], warnings: [], stopped: true, elapsed_ms: 1400 });
  await running;
  assert.match(get('status').textContent, /results are partial/);
  assert.equal(get('export').disabled, false);
  assert.equal(get('findings').children.length, 1);
  assert.equal(get('findings').children[0], card, 'completion should reuse the visible finding card');
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

test('large reports paginate 50 cards, create details lazily, and export all findings', async () => {
  const findings = Array.from({ length: 123 }, (_, i) => ({ signature: `record-${i}`, path: `C:/file-${i}`, sha256: 'a'.repeat(64),
    size_bytes: 3, signature_source: 'bundled', detection_method: 'Exact SHA-256 match', reason: 'Match' }));
  const { get, exported } = app(async () => ({ scanned: 123, signatures: 10, skipped: 0, findings, warnings: [], elapsed_ms: 20 }));
  get('target').value = 'C:/samples';
  await get('scan').events.click();
  assert.equal(get('findings').children.length, 50);
  assert.match(get('findings-page').textContent, /Page 1 of 3/);
  assert.ok(get('findings').children.every((card) => card.children[2].children.length === 1));
  get('findings-next').events.click();
  assert.equal(get('findings').children.length, 50);
  assert.match(get('findings').children[0].children[0].textContent, /record-50/);
  get('findings-next').events.click();
  assert.equal(get('findings').children.length, 23);
  assert.equal(get('findings-next').disabled, true);
  get('findings-prev').events.click();
  assert.equal(get('findings').children.length, 50);
  get('export').events.click();
  assert.equal(JSON.parse(await exported().text()).findings.length, 123);
});

test('slow history refresh does not keep scan controls locked', async () => {
  let listingCalls = 0;
  let finishRefresh;
  const { get } = app(undefined, [], () => {
    if (++listingCalls === 1) return { entries: [], warnings: [] };
    return new Promise((resolve) => { finishRefresh = resolve; });
  });
  get('target').value = 'C:/samples';
  await get('scan').events.click();
  assert.equal(listingCalls, 2);
  assert.equal(get('scan').disabled, false);
  assert.equal(get('choose-file').disabled, false);
  assert.equal(get('export').disabled, false);
  finishRefresh({ entries: [], warnings: [] });
});

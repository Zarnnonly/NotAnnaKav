const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');

function app(backend = async () => ({ scanned: 1, signatures: 10, skipped: 0, findings: [], warnings: [] })) {
  const elements = new Map();
  const element = () => ({
    value: '', checked: false, disabled: false, hidden: false, textContent: '',
    events: {}, classList: { add() {}, remove() {} },
    addEventListener(name, callback) { this.events[name] = callback; },
    replaceChildren() {}, append() {},
  });
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  };
  const calls = [];
  const context = vm.createContext({
    document: { getElementById: get, createElement: element },
    window: { __TAURI__: { core: { invoke: async (name, args) => {
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

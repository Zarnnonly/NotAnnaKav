const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { readFileSync } = require('node:fs');

const rows = [
  { pid: 12, process: 'browser.exe', executable: 'C:/browser.exe', family: 'IPv4', local: '127.0.0.1:5000', remote: '1.2.3.4:443', state: 'ESTABLISHED', listening: false },
  { pid: 4, process: 'System', executable: null, process_note: 'Restricted', family: 'IPv6', local: '[::]:80', remote: null, state: 'LISTEN', listening: true, binding: 'All interfaces' },
];
function app(backend = async () => ({ connections: rows, captured_at_ms: 1000, warnings: [] })) {
  const elements = new Map();
  const element = () => ({ value: '', hidden: false, disabled: false, textContent: '', children: [], events: {},
    classList: { toggle() {} }, setAttribute() {}, append(...items) { this.children.push(...items); },
    replaceChildren() { this.children = []; }, addEventListener(name, fn) { this.events[name] = fn; } });
  const get = (id) => { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); };
  get('network-mode').value = 'all';
  const timers = new Map(); let sequence = 0; let calls = 0; const scans = [];
  vm.runInNewContext(readFileSync(require.resolve('../ui/network.js'), 'utf8'), {
    document: { getElementById: get, createElement: element },
    setTimeout(fn) { timers.set(++sequence, fn); return sequence; }, clearTimeout(id) { timers.delete(id); },
    window: { __TAURI__: { core: { invoke: async (name) => { assert.equal(name, 'network_snapshot'); calls++; return backend(); } } },
      scanNetworkExecutable(path) { scans.push(path); return true; } },
  });
  return { get, timers, scans, calls: () => calls };
}
const settle = () => new Promise((resolve) => setImmediate(resolve));

test('sidebar loads network on demand, filters listeners and IPs, and sends executable to scanner', async () => {
  const { get, calls, scans, timers } = app();
  assert.equal(calls(), 0);
  get('nav-network').events.click(); await settle();
  assert.equal(get('network-view').hidden, false);
  assert.equal(get('scanner-view').hidden, true);
  assert.equal(get('network-rows').children.length, 2);
  assert.equal(get('network-established').textContent, '1');
  assert.equal(get('network-rows').children[1].children[3].disabled, true);
  get('network-mode').value = 'listeners'; get('network-mode').events.change();
  assert.equal(get('network-rows').children.length, 1);
  assert.match(get('network-rows').children[0].children[1].textContent, /All interfaces/);
  get('network-mode').value = 'all'; get('network-mode').events.change();
  get('network-filter').value = '1.2.3.4'; get('network-filter').events.input();
  assert.equal(get('network-rows').children.length, 1);
  get('network-rows').children[0].children[3].events.click();
  assert.deepEqual(scans, ['C:/browser.exe']);
  assert.equal(get('scanner-view').hidden, false);
  assert.equal(timers.size, 0);
});

test('requests do not overlap, Pause stops polling, and refresh remains available', async () => {
  let complete;
  const { get, calls, timers } = app(() => new Promise((resolve) => { complete = resolve; }));
  get('nav-network').events.click();
  get('network-refresh').events.click();
  assert.equal(calls(), 1);
  get('network-pause').events.click();
  complete({ connections: rows, captured_at_ms: 1000, warnings: [] }); await settle();
  assert.equal(timers.size, 0);
  assert.match(get('network-status').textContent, /Paused/);
  get('network-refresh').events.click(); assert.equal(calls(), 2);
  complete({ connections: [], captured_at_ms: 2000, warnings: [] }); await settle();
  assert.equal(timers.size, 0);
  get('network-pause').events.click(); assert.equal(calls(), 3);
  get('nav-scanner').events.click();
  complete({ connections: rows, captured_at_ms: 3000, warnings: [] }); await settle();
  assert.equal(timers.size, 0);
  assert.equal(get('network-total').textContent, '0', 'late response after leaving is ignored');
});

test('refresh failures retain entries and identify them as a previous snapshot', async () => {
  let fail = false;
  const { get } = app(async () => { if (fail) throw new Error('Windows unavailable'); return { connections: rows, captured_at_ms: 1000, warnings: [] }; });
  get('nav-network').events.click(); await settle(); fail = true;
  await get('network-refresh').events.click();
  assert.equal(get('network-rows').children.length, 2);
  assert.match(get('network-status').textContent, /previous snapshot/);
});

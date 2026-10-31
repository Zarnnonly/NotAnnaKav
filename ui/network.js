(() => {
  const el = (id) => document.getElementById(id);
  let visible = false;
  let paused = false;
  let busy = false;
  let timer;
  let generation = 0;
  let snapshot;
  let page = 0;
  const pageSize = 50;
  const expanded = new Set();
  const rowKey = (row) => [row.pid, row.family, row.local, row.remote, row.executable].join('|');
  const cancelTimer = () => { if (timer) clearTimeout(timer); timer = undefined; };
  const switchView = (network) => {
    visible = network;
    generation++;
    cancelTimer();
    el('scanner-view').hidden = network;
    el('network-view').hidden = !network;
    el('nav-network').classList.toggle('active', network);
    el('nav-scanner').classList.toggle('active', !network);
    el('nav-network').setAttribute('aria-pressed', String(network));
    el('nav-scanner').setAttribute('aria-pressed', String(!network));
    el('workspace-title').textContent = network ? 'WORKSPACE / NETWORK MONITOR' : 'WORKSPACE / THREAT SCANNER';
    if (network && !paused) void refresh();
  };
  const render = () => {
    if (!snapshot) return;
    const query = el('network-filter').value.trim().toLowerCase();
    const mode = el('network-mode').value;
    const rows = snapshot.connections.filter((row) =>
      (mode !== 'listeners' || row.listening) && (mode !== 'connections' || !row.listening)
      && [row.process, row.pid, row.executable, row.local, row.remote, row.state, row.family, row.binding]
        .join(' ').toLowerCase().includes(query));
    el('network-total').textContent = snapshot.connections.length.toLocaleString();
    el('network-established').textContent = snapshot.connections.filter((r) => r.state === 'ESTABLISHED').length.toLocaleString();
    el('network-listeners').textContent = snapshot.connections.filter((r) => r.listening).length.toLocaleString();
    el('network-shown').textContent = rows.length.toLocaleString();
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    page = Math.min(page, pages - 1);
    el('network-page').textContent = `Page ${page + 1} of ${pages}`;
    el('network-prev').disabled = page === 0;
    el('network-next').disabled = page === pages - 1;
    el('network-rows').replaceChildren();
    if (!rows.length) {
      const empty = document.createElement('p'); empty.className = 'empty'; empty.textContent = 'No TCP entries match this filter.';
      el('network-rows').append(empty);
    }
    for (const row of rows.slice(page * pageSize, (page + 1) * pageSize)) {
      const card = document.createElement('article'); card.className = 'network-entry';
      const title = document.createElement('p'); title.textContent = `${row.process} | PID ${row.pid} | ${row.family} | ${row.state}`;
      const endpoints = document.createElement('p');
      endpoints.textContent = row.listening ? `${row.local} | ${row.binding}` : `${row.local} → ${row.remote ?? 'Unavailable'}`;
      const details = document.createElement('details');
      const summary = document.createElement('summary'); summary.textContent = 'Process details'; details.append(summary);
      let populated = false;
      const populate = () => {
        if (details.open) expanded.add(rowKey(row)); else expanded.delete(rowKey(row));
        if (!details.open || populated) return;
        populated = true;
        const path = document.createElement('p'); path.textContent = row.executable ?? row.process_note ?? 'Executable unavailable.';
        const note = document.createElement('p'); note.textContent = 'This path was observed in a snapshot. Processes can exit or change before inspection.';
        details.append(path, note);
      };
      details.addEventListener('toggle', populate);
      if (expanded.has(rowKey(row))) { details.open = true; populate(); }
      const scan = document.createElement('button'); scan.className = 'secondary'; scan.textContent = 'Scan executable';
      scan.disabled = !row.executable;
      scan.title = row.executable ?? row.process_note ?? 'Executable unavailable';
      scan.addEventListener('click', () => {
        if (window.scanNetworkExecutable(row.executable)) switchView(false);
        else el('network-status').textContent = 'Finish or stop the current file inspection before scanning another executable.';
      });
      card.append(title, endpoints, details, scan); el('network-rows').append(card);
    }
  };
  const refresh = async () => {
    if (!visible || busy) return;
    cancelTimer();
    busy = true;
    const request = generation;
    el('network-refresh').disabled = true;
    el('network-status').textContent = 'Reading Windows TCP tables...';
    try {
      const result = await window.__TAURI__.core.invoke('network_snapshot');
      if (!visible || request !== generation) return;
      snapshot = result;
      const currentKeys = new Set(result.connections.map(rowKey));
      for (const key of expanded) if (!currentKeys.has(key)) expanded.delete(key);
      render();
      el('network-status').textContent = `${paused ? 'Paused' : 'Live · refresh every 2 seconds'} | Snapshot: ${new Date(result.captured_at_ms).toLocaleTimeString()}${result.warnings.length ? ` | ${result.warnings.join(' ')}` : ''}`;
    } catch (error) {
      if (visible && request === generation) el('network-status').textContent = `Network refresh failed: ${error}. Displayed entries, if any, are from the previous snapshot.`;
    } finally {
      busy = false;
      el('network-refresh').disabled = false;
      if (visible && !paused) timer = setTimeout(refresh, 2000);
    }
  };
  el('nav-scanner').addEventListener('click', () => switchView(false));
  el('nav-network').addEventListener('click', () => switchView(true));
  el('network-refresh').addEventListener('click', refresh);
  el('network-pause').addEventListener('click', () => {
    paused = !paused;
    cancelTimer();
    el('network-pause').textContent = paused ? 'Resume' : 'Pause';
    if (!paused) void refresh();
    else el('network-status').textContent = 'Paused. Displayed entries remain a snapshot. Refresh now is still available.';
  });
  for (const [id, event] of [['network-filter', 'input'], ['network-mode', 'change']]) {
    el(id).addEventListener(event, () => { page = 0; render(); });
  }
  el('network-prev').addEventListener('click', () => { if (page > 0) { page--; render(); } });
  el('network-next').addEventListener('click', () => { page++; render(); });
})();

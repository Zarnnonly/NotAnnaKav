const $ = (id) => document.getElementById(id);
const invoke = (name, args) => {
  if (!window.__TAURI__) throw new Error('Open NotAnnaKav through the Tauri desktop application.');
  return window.__TAURI__.core.invoke(name, args);
};
let report;
let activeScanId = null;
let nextScanId = 0;
let stopping = false;
window.scanNetworkExecutable = (path) => {
  if (activeScanId || !path) return false;
  $('target').value = path;
  $('scan').click();
  return true;
};
let historyRequest = 0;
let openRequest = 0;
const FINDINGS_PER_PAGE = 50;
let viewFindings = [];
let findingPage = 0;
let renderedPage = -1;
let renderedCount = 0;
const bytes = (value) => `${Number(value ?? 0).toLocaleString()} bytes`;
const duration = (ms) => `${(Number(ms ?? 0) / 1000).toFixed(1)}s`;
const renderFinding = (finding) => {
  const card = document.createElement('article');
  const title = document.createElement('p');
  title.textContent = `SIGNATURE MATCH / ${finding.signature}`;
  const path = document.createElement('p'); path.textContent = finding.path;
  const details = document.createElement('details');
  const summary = document.createElement('summary'); summary.textContent = 'View finding details';
  let populated = false;
  details.addEventListener('toggle', () => {
    if (!details.open || populated) return;
    populated = true;
    const fields = document.createElement('dl');
  for (const [label, value] of [
    ['Detection method', finding.detection_method],
    ['Why it matched', finding.reason],
    ['Full path', finding.path],
    ['File size', bytes(finding.size_bytes)],
    ['SHA-256', finding.sha256],
    ['Signature record', finding.signature],
    ['Signature source', finding.signature_source],
    ['Action taken', 'Reported only. The file has not been modified or quarantined.'],
  ]) {
    const term = document.createElement('dt'); term.textContent = label;
    const description = document.createElement('dd'); description.textContent = value;
    fields.append(term, description);
  }
    details.append(fields);
  });
  details.append(summary); card.append(title, path, details);
  $('findings').append(card);
};

const renderFindingsPage = () => {
  const pages = Math.max(1, Math.ceil(viewFindings.length / FINDINGS_PER_PAGE));
  findingPage = Math.min(findingPage, pages - 1);
  $('findings-page').textContent = `Page ${findingPage + 1} of ${pages} | ${viewFindings.length.toLocaleString()} matches`;
  $('findings-prev').disabled = findingPage === 0;
  $('findings-next').disabled = findingPage >= pages - 1;
  if (!viewFindings.length) {
    $('findings').replaceChildren();
    const p = document.createElement('p'); p.className = 'empty';
    p.textContent = activeScanId && !report ? 'No matches reported yet. Inspection is in progress.'
      : report?.stopped ? 'No matches in the files checked so far. Inspection was stopped before completion.'
      : 'No signature matches found. Review any warnings for incomplete coverage.';
    $('findings').append(p);
    renderedPage = -1;
    renderedCount = 0;
    return;
  }
  if (renderedPage !== findingPage) {
    $('findings').replaceChildren();
    renderedPage = findingPage;
    renderedCount = 0;
  }
  const start = findingPage * FINDINGS_PER_PAGE;
  const count = Math.min(FINDINGS_PER_PAGE, viewFindings.length - start);
  for (; renderedCount < count; renderedCount++) renderFinding(viewFindings[start + renderedCount]);
};
$('findings-prev').addEventListener('click', () => { if (findingPage > 0) { findingPage--; renderFindingsPage(); } });
$('findings-next').addEventListener('click', () => {
  if ((findingPage + 1) * FINDINGS_PER_PAGE < viewFindings.length) { findingPage++; renderFindingsPage(); }
});

const showReport = (result, historical = false) => {
  report = result;
  $('scanned').textContent = result.scanned.toLocaleString();
  $('matches').textContent = result.findings.length.toLocaleString();
  $('signatures').textContent = result.signatures.toLocaleString();
  $('skipped').textContent = result.skipped.toLocaleString();
  $('status').textContent = result.stopped
    ? 'Inspection stopped. These results are partial; remaining files have not been checked.'
    : result.findings.length
    ? 'Inspection complete. Signature matches require investigation.'
    : 'Inspection complete. No known signatures matched the files successfully hashed.';
  if (result.history_error) $('status').textContent += ` ${result.history_error}. You can still export this report.`;
  const time = result.completed_at_ms ? new Date(result.completed_at_ms).toLocaleString() : result.completedAt;
  $('report-context').hidden = false;
  $('report-context').textContent = `${historical ? 'Saved inspection' : 'Latest inspection'} | ${time ?? ''} | ${result.target} | Database: ${result.database}`;
  $('scan-progress').hidden = false;
  $('activity').hidden = true;
  $('current-file').textContent = '';
  $('progress-summary').textContent = `${result.stopped ? 'Stopped' : 'Completed'} | ${result.scanned.toLocaleString()} files hashed | ${duration(result.elapsed_ms)} elapsed`;
  if (historical) { findingPage = 0; renderedPage = -1; }
  viewFindings = result.findings;
  renderFindingsPage();
  $('warning-section').hidden = !result.warnings.length;
  $('warnings').textContent = result.warnings.join('\n');
  $('export').disabled = false;
};

const refreshHistory = async () => {
  const request = ++historyRequest;
  try {
    const history = await invoke('list_history');
    if (request !== historyRequest) return;
    $('history-list').replaceChildren();
    $('history-status').textContent = history.entries.length
      ? 'Most recent saved inspections. Open a report to view its findings or export it.'
      : 'No saved inspections yet. Completed and stopped scans are saved automatically.';
    if (history.warnings.length) $('history-status').textContent += ` ${history.warnings.join(' ')}`;
    for (const entry of history.entries) {
      const row = document.createElement('div'); row.className = 'history-entry';
      const text = document.createElement('div');
      const title = document.createElement('p'); title.textContent = entry.target;
      const summary = document.createElement('p');
      summary.textContent = `${new Date(entry.completed_at_ms).toLocaleString()} | ${entry.stopped ? 'Stopped / partial' : 'Completed'} | ${entry.scanned} files | ${entry.matches} matches`;
      text.append(title, summary);
      const button = document.createElement('button'); button.className = 'secondary'; button.textContent = 'Open report';
      button.addEventListener('click', async () => {
        if (activeScanId) { $('history-status').textContent = 'Finish or stop the active inspection before opening a saved report.'; return; }
        const request = ++openRequest;
        const epoch = nextScanId;
        button.disabled = true;
        try {
          const saved = await invoke('read_history', { id: entry.id });
          if (activeScanId || epoch !== nextScanId || request !== openRequest) return;
          showReport(saved, true);
        } catch (error) { $('history-status').textContent = `Could not open report: ${error}`; }
        finally { button.disabled = false; }
      });
      row.append(text, button); $('history-list').append(row);
    }
  } catch (error) {
    if (request === historyRequest) $('history-status').textContent = `Could not load history: ${error}`;
  }
};
$('refresh-history').addEventListener('click', refreshHistory);
refreshHistory();

$('choose-file').addEventListener('click', async () => {
  try {
    const path = await invoke('choose_file');
    if (path && !activeScanId) $('target').value = path;
  } catch (error) { $('status').textContent = String(error); }
});

const setupDrop = async () => {
  try {
    await window.__TAURI__.webview.getCurrentWebview().onDragDropEvent(({ payload }) => {
      $('drop-zone').classList.remove('drag-over');
      if (activeScanId) {
        if (payload.type === 'drop') $('drop-zone').textContent = 'Finish or stop this scan before selecting another target.';
        return;
      }
      if (payload.type === 'enter' || payload.type === 'over') $('drop-zone').classList.add('drag-over');
      if (payload.type !== 'drop') return;
      if (payload.paths.length !== 1) {
        $('drop-zone').textContent = 'Drop one file or folder at a time. The current target has not changed.';
        return;
      }
      $('target').value = payload.paths[0];
      $('drop-zone').textContent = 'Target selected. Click Start inspection to scan it.';
    });
  } catch (error) { $('drop-zone').textContent = `Drag-and-drop unavailable. Use Choose file or Browse folder. ${error}`; }
};
setupDrop();

$('stop').addEventListener('click', async () => {
  const id = activeScanId;
  if (!id || stopping) return;
  stopping = true;
  $('stop').disabled = true;
  $('status').textContent = 'Stopping inspection. Waiting for the current filesystem operation to return...';
  try {
    await invoke('stop_scan', { scanId: id });
  } catch (error) {
    if (activeScanId !== id) return;
    stopping = false;
    $('stop').disabled = false;
    $('status').textContent = `Could not stop inspection: ${error}. You can try again.`;
  }
});
const syncDatabaseSelection = () => {
  const custom = $('custom-database').checked;
  $('custom-database-fields').hidden = !custom;
  $('database').disabled = !custom;
  $('choose-database').disabled = !custom;
};
$('custom-database').addEventListener('change', syncDatabaseSelection);
syncDatabaseSelection();
for (const name of ['target', 'database']) {
  $(`choose-${name}`).addEventListener('click', async () => {
    try {
      const path = await invoke('choose_folder');
      if (path && !activeScanId) $(name).value = path;
    } catch (error) { $('status').textContent = String(error); }
  });
}
$('scan').addEventListener('click', async () => {
  if (activeScanId) return;
  const target = $('target').value.trim();
  const database = $('custom-database').checked ? $('database').value.trim() : null;
  if (!target) { $('status').textContent = 'Select a file or folder to scan.'; return; }
  if (database === '') { $('status').textContent = 'Select your custom database folder or turn off the custom database option.'; return; }
  report = undefined;
  viewFindings = [];
  findingPage = 0;
  renderedPage = -1;
  renderedCount = 0;
  $('report-context').hidden = true;
  const scanId = `${Date.now()}-${++nextScanId}`;
  activeScanId = scanId;
  stopping = false;
  let acceptingProgress = true;
  $('export').disabled = true;
  $('stop').disabled = true;
  $('scan-progress').hidden = false;
  $('activity').hidden = false;
  $('progress-summary').textContent = 'Preparing inspection...';
  $('current-file').textContent = '';
  for (const id of ['scanned', 'matches', 'signatures', 'skipped']) $(id).textContent = '—';
  $('findings').replaceChildren();
  $('findings-page').textContent = 'Page 1 of 1 | 0 matches';
  $('findings-prev').disabled = true;
  $('findings-next').disabled = true;
  $('warning-section').hidden = true;
  for (const id of ['scan', 'target', 'database', 'choose-target', 'choose-file', 'choose-database', 'custom-database']) $(id).disabled = true;
  $('status').textContent = 'Inspection in progress. Large folders may take several minutes…';
  $('status').classList.add('running');
  try {
    const onProgress = new window.__TAURI__.core.Channel();
    onProgress.onmessage = (progress) => {
      if (activeScanId !== scanId || !acceptingProgress) return;
      $('scanned').textContent = progress.scanned.toLocaleString();
      $('matches').textContent = progress.matches.toLocaleString();
      $('signatures').textContent = progress.signatures.toLocaleString();
      $('skipped').textContent = progress.skipped.toLocaleString();
      $('progress-summary').textContent = `${progress.phase === 'loading' ? 'Loading signatures' : 'Inspecting files'} | ${progress.scanned.toLocaleString()} files hashed | ${duration(progress.elapsed_ms)} elapsed`;
      $('current-file').textContent = progress.current_file
        ? `${progress.current_file}\n${bytes(progress.file_bytes)} read / ${bytes(progress.file_size)} file size`
        : '';
      $('stop').disabled = stopping || !['loading', 'scanning'].includes(progress.phase);
      if (progress.findings?.length && progress.finding_offset === viewFindings.length) {
        viewFindings.push(...progress.findings);
        renderFindingsPage();
      }
    };
    const result = await invoke('scan_folder', { target, database, scanId, onProgress });
    acceptingProgress = false;
    showReport({ target, database: database ?? 'bundled', completedAt: new Date().toISOString(), ...result });
    void refreshHistory();
  } catch (error) {
    $('status').textContent = `Inspection failed: ${error}`;
    $('progress-summary').textContent = 'Inspection failed. Any live findings shown are incomplete.';
  }
  finally {
    acceptingProgress = false;
    activeScanId = null;
    $('stop').disabled = true;
    $('activity').hidden = true;
    $('status').classList.remove('running');
    for (const id of ['scan', 'target', 'custom-database', 'choose-target', 'choose-file']) $(id).disabled = false;
    syncDatabaseSelection();
  }
});
$('export').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'notannakav-report.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

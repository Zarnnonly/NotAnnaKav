const $ = (id) => document.getElementById(id);
const invoke = (name, args) => {
  if (!window.__TAURI__) throw new Error('Open NotAnnaKav through the Tauri desktop application.');
  return window.__TAURI__.core.invoke(name, args);
};
let report;
let activeScanId = null;
let nextScanId = 0;
let stopping = false;
const bytes = (value) => `${Number(value ?? 0).toLocaleString()} bytes`;
const duration = (ms) => `${(Number(ms ?? 0) / 1000).toFixed(1)}s`;
const renderFinding = (finding) => {
  const card = document.createElement('article');
  const title = document.createElement('p');
  title.textContent = `SIGNATURE MATCH / ${finding.signature}`;
  const path = document.createElement('p'); path.textContent = finding.path;
  const details = document.createElement('details');
  const summary = document.createElement('summary'); summary.textContent = 'View finding details';
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
  details.append(summary, fields); card.append(title, path, details);
  $('findings').append(card);
};

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
      if (path) $(name).value = path;
    } catch (error) { $('status').textContent = String(error); }
  });
}
$('scan').addEventListener('click', async () => {
  if (activeScanId) return;
  const target = $('target').value.trim();
  const database = $('custom-database').checked ? $('database').value.trim() : null;
  if (!target) { $('status').textContent = 'Select a folder to scan.'; return; }
  if (database === '') { $('status').textContent = 'Select your custom database folder or turn off the custom database option.'; return; }
  report = undefined;
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
  $('warning-section').hidden = true;
  for (const id of ['scan', 'target', 'database', 'choose-target', 'choose-database', 'custom-database']) $(id).disabled = true;
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
      if (progress.finding) renderFinding(progress.finding);
    };
    const result = await invoke('scan_folder', { target, database, scanId, onProgress });
    acceptingProgress = false;
    report = { target, database: database ?? 'bundled', completedAt: new Date().toISOString(), ...result };
    $('scanned').textContent = result.scanned.toLocaleString();
    $('matches').textContent = result.findings.length.toLocaleString();
    $('signatures').textContent = result.signatures.toLocaleString();
    $('skipped').textContent = result.skipped.toLocaleString();
    $('status').textContent = result.stopped
      ? 'Inspection stopped. These results are partial; remaining files have not been checked.'
      : result.findings.length
      ? 'Inspection complete. Signature matches require investigation.'
      : 'Inspection complete. No known signatures matched the files successfully hashed.';
    $('progress-summary').textContent = `${result.stopped ? 'Stopped' : 'Completed'} | ${result.scanned.toLocaleString()} files hashed | ${duration(result.elapsed_ms)} elapsed`;
    $('findings').replaceChildren();
    if (!result.findings.length) {
      const p = document.createElement('p');
      p.className = 'empty'; p.textContent = result.stopped
        ? 'No matches in the files checked so far. Inspection was stopped before completion.'
        : 'No signature matches found. Review any warnings for incomplete coverage.';
      $('findings').append(p);
    }
    for (const finding of result.findings) renderFinding(finding);
    $('warning-section').hidden = !result.warnings.length;
    $('warnings').textContent = result.warnings.join('\n');
    $('export').disabled = false;
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
    for (const id of ['scan', 'target', 'custom-database', 'choose-target']) $(id).disabled = false;
    syncDatabaseSelection();
  }
});
$('export').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'notannakav-report.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

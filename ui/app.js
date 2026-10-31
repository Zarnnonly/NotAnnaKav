const $ = (id) => document.getElementById(id);
const invoke = (name, args) => {
  if (!window.__TAURI__) throw new Error('Open NotAnnaKav through the Tauri desktop application.');
  return window.__TAURI__.core.invoke(name, args);
};
let report;
for (const name of ['target', 'database']) {
  $(`choose-${name}`).addEventListener('click', async () => {
    try {
      const path = await invoke('choose_folder');
      if (path) $(name).value = path;
    } catch (error) { $('status').textContent = String(error); }
  });
}
$('scan').addEventListener('click', async () => {
  const target = $('target').value.trim();
  const database = $('database').value.trim();
  if (!target || !database) { $('status').textContent = 'Select both a scan target and a signature database.'; return; }
  report = undefined;
  $('export').disabled = true;
  for (const id of ['scanned', 'matches', 'signatures', 'skipped']) $(id).textContent = '—';
  $('findings').replaceChildren();
  $('warning-section').hidden = true;
  for (const id of ['scan', 'target', 'database', 'choose-target', 'choose-database']) $(id).disabled = true;
  $('status').textContent = 'Inspection in progress. Large folders may take several minutes…';
  $('status').classList.add('running');
  try {
    const result = await invoke('scan_folder', { target, database });
    report = { target, database, completedAt: new Date().toISOString(), ...result };
    $('scanned').textContent = result.scanned.toLocaleString();
    $('matches').textContent = result.findings.length.toLocaleString();
    $('signatures').textContent = result.signatures.toLocaleString();
    $('skipped').textContent = result.skipped.toLocaleString();
    $('status').textContent = result.findings.length
      ? 'Inspection complete. Signature matches require investigation.'
      : 'Inspection complete. No known signatures matched the files successfully hashed.';
    if (!result.findings.length) {
      const p = document.createElement('p');
      p.className = 'empty'; p.textContent = 'No signature matches found. Review any warnings for incomplete coverage.';
      $('findings').append(p);
    }
    for (const finding of result.findings) {
      const card = document.createElement('article');
      for (const value of [`SIGNATURE MATCH / ${finding.signature}`, finding.path, `SHA-256: ${finding.sha256}`]) {
        const p = document.createElement('p'); p.textContent = value; card.append(p);
      }
      $('findings').append(card);
    }
    $('warning-section').hidden = !result.warnings.length;
    $('warnings').textContent = result.warnings.join('\n');
    $('export').disabled = false;
  } catch (error) { $('status').textContent = `Inspection failed: ${error}`; }
  finally {
    $('status').classList.remove('running');
    for (const id of ['scan', 'target', 'database', 'choose-target', 'choose-database']) $(id).disabled = false;
  }
});
$('export').addEventListener('click', () => {
  if (!report) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a'); link.href = url; link.download = 'notannakav-report.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

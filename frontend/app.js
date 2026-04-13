const API = '';

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let networks = {};
let scanning = false;
let sse = null;

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  initPlugins();
  initInterfaces();
  fetchInitialState();
  wireButtons();
});

// ---------------------------------------------------------------------------
// initInterfaces
// ---------------------------------------------------------------------------
async function initInterfaces() {
  const select = document.getElementById('interface-select');
  try {
    const res = await fetch(`${API}/api/interfaces`);
    const ifaces = await res.json();

    // Remove all options except the placeholder
    while (select.options.length > 1) select.remove(1);

    if (ifaces.length === 0) {
      select.options[0].textContent = 'No monitor-mode interfaces found';
      return;
    }

    for (const iface of ifaces) {
      const opt = document.createElement('option');
      opt.value = iface;
      opt.textContent = iface;
      select.appendChild(opt);
    }
  } catch (err) {
    select.options[0].textContent = 'Failed to load interfaces';
  }
}

// ---------------------------------------------------------------------------
// initPlugins
// ---------------------------------------------------------------------------
async function initPlugins() {
  const list = document.getElementById('plugins-list');
  try {
    const res = await fetch(`${API}/api/plugins`);
    const data = await res.json();

    if (data.plugins.length > 0) {
      // Remove default "None loaded" item
      const defaultLi = list.querySelector('.muted');
      if (defaultLi) defaultLi.remove();

      for (const plugin of data.plugins) {
        const li = document.createElement('li');
        li.className = 'plugin-item';
        li.textContent = plugin.name;
        if (plugin.description) li.title = plugin.description;
        list.appendChild(li);
      }
    }

    for (const filename of Object.keys(data.errors || {})) {
      const li = document.createElement('li');
      li.style.color = 'var(--amber)';
      li.textContent = `Error: ${filename}`;
      li.title = data.errors[filename];
      list.appendChild(li);
    }
  } catch (err) {
    // Leave default state
  }
}

// ---------------------------------------------------------------------------
// wireButtons
// ---------------------------------------------------------------------------
function wireButtons() {
  document.getElementById('btn-start').addEventListener('click', startScan);
  document.getElementById('btn-stop').addEventListener('click', stopScan);
  document.getElementById('drawer-close').addEventListener('click', closeDrawer);

  for (const btn of document.querySelectorAll('.tab-btn')) {
    btn.addEventListener('click', () => {
      for (const b of document.querySelectorAll('.tab-btn')) b.classList.remove('active');
      btn.classList.add('active');

      for (const panel of document.querySelectorAll('.tab-panel')) {
        panel.hidden = true;
      }
      document.getElementById(`panel-${btn.dataset.tab}`).hidden = false;
    });
  }
}

// ---------------------------------------------------------------------------
// startScan
// ---------------------------------------------------------------------------
async function startScan() {
  const select = document.getElementById('interface-select');
  const iface = select.value;
  if (!iface) {
    alert('Please select an interface first.');
    return;
  }

  try {
    const res = await fetch(`${API}/api/scan/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: iface }),
    });
    await res.json();

    scanning = true;
    networks = {};
    document.getElementById('networks-body').innerHTML = '';
    document.getElementById('threats-feed').innerHTML = '';
    document.getElementById('count-networks').textContent = '0';
    document.getElementById('count-flagged').textContent = '0';
    document.getElementById('count-threats').textContent = '0';

    setStatus('active', `Scanning on ${iface}`);
    document.getElementById('btn-start').disabled = true;
    document.getElementById('btn-stop').disabled = false;

    connectSSE();
  } catch (err) {
    alert(`Failed to start scan: ${err.message}`);
  }
}

// ---------------------------------------------------------------------------
// stopScan
// ---------------------------------------------------------------------------
async function stopScan() {
  try {
    await fetch(`${API}/api/scan/stop`, { method: 'POST' });
  } catch (_) {
    // best-effort
  }

  scanning = false;
  setStatus('idle', 'Idle');
  document.getElementById('btn-start').disabled = false;
  document.getElementById('btn-stop').disabled = true;

  if (sse) {
    sse.close();
    sse = null;
  }
}

// ---------------------------------------------------------------------------
// setStatus
// ---------------------------------------------------------------------------
function setStatus(state, text) {
  document.getElementById('status-text').textContent = text;
  const dot = document.getElementById('status-dot');
  if (state === 'active') {
    dot.classList.add('active');
  } else {
    dot.classList.remove('active');
  }
}

// ---------------------------------------------------------------------------
// connectSSE
// ---------------------------------------------------------------------------
function connectSSE() {
  if (sse) {
    sse.close();
  }

  sse = new EventSource(`${API}/api/stream`);

  sse.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'network') handleNetworkEvent(data.data);
    else if (data.type === 'deauth') handleThreatEvent(data.data);
    else if (data.type === 'flood') handleFloodEvent(data.data);
  };

  sse.onerror = () => {
    if (scanning) {
      setStatus('active', 'Reconnecting...');
      sse.close();
      sse = null;
      setTimeout(connectSSE, 3000);
    }
  };
}

// ---------------------------------------------------------------------------
// handleNetworkEvent
// ---------------------------------------------------------------------------
function handleNetworkEvent(network) {
  network.flagged = network.Security.includes('WEP') || network.Security === 'Open';

  if (network.BSSID in networks) {
    // Update signal cell only
    const row = document.querySelector(`tr[data-bssid="${CSS.escape(network.BSSID)}"]`);
    if (row) {
      const signalTd = row.cells[6];
      const newTd = signalCell(network.Signal);
      signalTd.replaceWith(newTd);
    }
    networks[network.BSSID] = network;
    return;
  }

  networks[network.BSSID] = network;

  const countEl = document.getElementById('count-networks');
  countEl.textContent = parseInt(countEl.textContent, 10) + 1;

  if (network.flagged) {
    const flaggedEl = document.getElementById('count-flagged');
    flaggedEl.textContent = parseInt(flaggedEl.textContent, 10) + 1;
  }

  const tr = renderNetworkRow(network);
  const tbody = document.getElementById('networks-body');
  tbody.prepend(tr);

  tr.classList.add('row-enter');
  setTimeout(() => tr.classList.remove('row-enter'), 300);
}

// ---------------------------------------------------------------------------
// renderNetworkRow
// ---------------------------------------------------------------------------
function renderNetworkRow(network) {
  const tr = document.createElement('tr');
  tr.dataset.bssid = network.BSSID;
  if (network.flagged) tr.classList.add('flagged');
  tr.addEventListener('click', () => openDrawer(network));

  // 1. Status badge
  const tdStatus = document.createElement('td');
  const badge = document.createElement('span');
  badge.className = network.flagged ? 'badge badge-flagged' : 'badge badge-ok';
  badge.textContent = network.flagged ? 'FLAGGED' : 'OK';
  tdStatus.appendChild(badge);

  // 2. SSID
  const tdSsid = document.createElement('td');
  const ssid = network.SSID ?? '';
  tdSsid.textContent = ssid.length > 24 ? ssid.slice(0, 24) + '…' : ssid;

  // 3. BSSID
  const tdBssid = document.createElement('td');
  const bssidSpan = document.createElement('span');
  bssidSpan.className = 'mono';
  bssidSpan.textContent = network.BSSID ?? '—';
  tdBssid.appendChild(bssidSpan);

  // 4. Standard
  const tdStandard = document.createElement('td');
  tdStandard.textContent = network.Standard ?? '—';

  // 5. Security
  const tdSecurity = document.createElement('td');
  tdSecurity.textContent = network.Security ?? '—';
  if (network.flagged) tdSecurity.style.color = 'var(--red)';

  // 6. Channel
  const tdChannel = document.createElement('td');
  tdChannel.textContent = network.Channel ?? '—';

  // 7. Signal
  const tdSignal = signalCell(network.Signal);

  // 8. Vendor (plugin field)
  const tdVendor = document.createElement('td');
  const vendorSpan = document.createElement('span');
  vendorSpan.className = 'mono';
  vendorSpan.style.color = 'var(--text-muted)';
  vendorSpan.textContent = network.Vendor ?? '—';
  tdVendor.appendChild(vendorSpan);

  tr.append(tdStatus, tdSsid, tdBssid, tdStandard, tdSecurity, tdChannel, tdSignal, tdVendor);
  return tr;
}

// ---------------------------------------------------------------------------
// signalCell
// ---------------------------------------------------------------------------
function signalCell(dBm) {
  const td = document.createElement('td');

  let bars = 0;
  if (dBm != null) {
    if (dBm >= -50) bars = 4;
    else if (dBm >= -65) bars = 3;
    else if (dBm >= -75) bars = 2;
    else if (dBm >= -85) bars = 1;
  }

  const barWrap = document.createElement('span');
  barWrap.className = 'signal-bars';
  for (let i = 0; i < 4; i++) {
    const s = document.createElement('span');
    if (i < bars) s.classList.add('lit');
    barWrap.appendChild(s);
  }

  td.appendChild(barWrap);
  td.appendChild(document.createTextNode(dBm != null ? ` ${dBm} dBm` : '—'));
  return td;
}

// ---------------------------------------------------------------------------
// handleThreatEvent
// ---------------------------------------------------------------------------
function handleThreatEvent(entry) {
  const countEl = document.getElementById('count-threats');
  countEl.textContent = parseInt(countEl.textContent, 10) + 1;

  const card = document.createElement('div');
  card.className = 'threat-card';

  const type = document.createElement('div');
  type.className = 'threat-type';
  type.textContent = 'Deauth Frame';

  const macs = document.createElement('div');
  macs.className = 'threat-macs';
  macs.textContent = `${entry.source} → ${entry.target}`;

  const meta = document.createElement('div');
  meta.className = 'threat-meta';
  meta.textContent = `Reason: ${entry.reason ?? 'unknown'} · ${timestamp()}`;

  card.append(type, macs, meta);
  document.getElementById('threats-feed').prepend(card);
}

// ---------------------------------------------------------------------------
// handleFloodEvent
// ---------------------------------------------------------------------------
function handleFloodEvent(entry) {
  const card = document.createElement('div');
  card.className = 'threat-card flood';

  const type = document.createElement('div');
  type.className = 'threat-type';
  type.textContent = 'FLOOD WARNING';

  const macs = document.createElement('div');
  macs.className = 'threat-macs';
  macs.textContent = `Attacker: ${entry.source}`;

  const meta = document.createElement('div');
  meta.className = 'threat-meta';
  meta.textContent = `${entry.count} frames detected · ${timestamp()}`;

  card.append(type, macs, meta);
  document.getElementById('threats-feed').prepend(card);
}

// ---------------------------------------------------------------------------
// openDrawer
// ---------------------------------------------------------------------------
function openDrawer(network) {
  document.getElementById('drawer-ssid').textContent = network.SSID;

  const content = document.getElementById('drawer-content');
  content.innerHTML = '';

  for (const [key, value] of Object.entries(network)) {
    if (key === 'flagged') continue;

    const row = document.createElement('div');
    row.className = 'drawer-row';

    const k = document.createElement('span');
    k.className = 'drawer-key';
    k.textContent = key;

    const v = document.createElement('span');
    v.className = 'drawer-val';
    v.textContent = value ?? '—';

    row.append(k, v);
    content.appendChild(row);
  }

  document.getElementById('detail-drawer').classList.add('open');
}

// ---------------------------------------------------------------------------
// closeDrawer
// ---------------------------------------------------------------------------
function closeDrawer() {
  document.getElementById('detail-drawer').classList.remove('open');
}

// ---------------------------------------------------------------------------
// fetchInitialState
// ---------------------------------------------------------------------------
async function fetchInitialState() {
  try {
    const [nRes, tRes] = await Promise.all([
      fetch(`${API}/api/networks`),
      fetch(`${API}/api/threats`),
    ]);
    const [networkList, threatList] = await Promise.all([nRes.json(), tRes.json()]);

    for (const network of networkList) {
      handleNetworkEvent(network);
    }

    for (const threat of threatList) {
      if ('count' in threat) {
        handleFloodEvent(threat);
      } else if ('source' in threat) {
        handleThreatEvent(threat);
      }
    }
  } catch (_) {
    // Server may not be reachable yet; SSE will hydrate state when scan starts
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function timestamp() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

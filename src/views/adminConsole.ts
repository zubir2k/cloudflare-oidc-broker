function escapeHtml(unsafe: unknown): string {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function renderAdminConsoleHtml(userEmail: string, adminBasePath: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Identity Operations Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='80' font-size='80'>🔐</text></svg>">
  <style>
    :root {
      --bg: #070d19;
      --card: #0d1527;
      --border: #1e293b;
      --text: #f8fafc;
      --muted: #94a3b8;
      --primary: #2563eb;
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 1.5rem;
      line-height: 1.5;
    }
    .container { max-width: 1200px; margin: 0 auto; width: 100%; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 1rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
      gap: 1rem;
    }
    h1 { font-size: 1.25rem; margin: 0; }
    .auth-tag {
      font-size: 0.8rem;
      color: var(--success);
      background: rgba(16, 185, 129, 0.1);
      border: 1px solid rgba(16, 185, 129, 0.2);
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-weight: 500;
    }
    .tabs {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1.5rem;
      border-bottom: 1px solid var(--border);
    }
    .tab-btn {
      background: transparent;
      color: var(--muted);
      border: none;
      padding: 0.75rem 1.25rem;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      font-size: 0.9rem;
    }
    .tab-btn.active { color: #38bdf8; border-bottom-color: #38bdf8; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 2rem;
    }
    .card h2 { font-size: 1rem; margin-top: 0; margin-bottom: 1rem; color: #38bdf8; }
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
    .secret-cell { display: inline-flex; align-items: center; gap: 0.3rem; }
    .secret-cell .icon-btn { background: none; border: none; cursor: pointer; padding: 0 0.15rem; color: var(--muted); font-size: 0.85rem; opacity: 0.6; line-height: 1; }
    .secret-cell .icon-btn:hover { opacity: 1; }
    .badge.pkce { background: #d1fae5; color: #065f46; }
    .badge.pkce-off { background: #fee2e2; color: #991b1b; }
    label { display: block; font-size: 0.75rem; color: var(--muted); margin-bottom: 0.35rem; text-transform: uppercase; font-weight: 600; }
    input, select {
      width: 100%;
      background: #030712;
      border: 1px solid var(--border);
      color: #fff;
      padding: 0.65rem;
      border-radius: 6px;
      font-size: 0.875rem;
      font-family: inherit;
    }
    input:focus, select:focus { outline: none; border-color: var(--primary); }
    input:disabled, select:disabled { background: #1e293b; color: var(--muted); cursor: not-allowed; }
    .form-actions { margin-top: 1.25rem; display: flex; justify-content: flex-end; gap: 0.5rem; }
    button.btn-submit { background: var(--primary); color: #fff; border: none; padding: 0.65rem 1.25rem; border-radius: 6px; font-weight: 600; cursor: pointer; }
    button.btn-cancel { background: transparent; border: 1px solid var(--muted); color: var(--muted); padding: 0.65rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; display: none; }
    .table-responsive { width: 100%; overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th { text-align: left; padding: 0.75rem; color: var(--muted); border-bottom: 1px solid var(--border); font-size: 0.75rem; text-transform: uppercase; white-space: nowrap; }
    td { padding: 0.85rem 0.75rem; border-bottom: 1px solid #1a2234; vertical-align: middle; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .break-all { word-break: break-all; }
    .badge { padding: 0.25rem 0.55rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; display: inline-block; }
    .badge.user { background: #1e3a8a; color: #93c5fd; }
    .badge.app { background: #312e81; color: #c7d2fe; }
    .badge.global { background: #065f46; color: #a7f3d0; }
    .badge.active { background: rgba(16, 185, 129, 0.15); color: var(--success); }
    .badge.inactive { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
    .muted { color: var(--muted); }
    .small { font-size: 0.75rem; }
    .actions { text-align: right; white-space: nowrap; }
    .btn-edit { background: transparent; border: 1px solid var(--warning); color: var(--warning); padding: 0.35rem 0.65rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; margin-right: 0.35rem; }
    .btn-del { background: transparent; border: 1px solid var(--danger); color: var(--danger); padding: 0.35rem 0.65rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; }
    .tab-content { display: none; width: 100%; }
    .tab-content.active { display: block !important; }
    .input-group { display: flex; gap: 0.5rem; }
    .input-group input { flex: 1; }
    .icon-btn-action { 
      background: var(--card); 
      border: 1px solid var(--border); 
      border-radius: 6px; 
      padding: 0 0.75rem; 
      cursor: pointer; 
      font-size: 1.1rem; 
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .icon-btn-action:hover { border-color: var(--primary); }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>Identity Operations Console</h1>
        <div class="muted small" style="margin-top: 0.25rem;">Downstream OIDC Client & Zero-Exposure Directory Management</div>
      </div>
      <div class="auth-tag">🔒 Authenticated: ${escapeHtml(userEmail)}</div>
    </div>

    <div class="tabs">
      <button class="tab-btn active" id="tabBtnClients" onclick="switchTab('tab-clients', this)">Client Applications</button>
      <button class="tab-btn" id="tabBtnUsers" onclick="switchTab('tab-users', this)">User Mappings</button>
    </div>

    <!-- TAB 1: CLIENT APPLICATIONS -->
    <div id="tab-clients" class="tab-content active">
      <div class="card" id="clientCard">
        <h2 id="clientFormTitle">Register Downstream Client Application</h2>
        <form id="clientForm">
          <div class="form-grid">
            <div>
              <label>Application Name</label>
              <input type="text" id="clientName" placeholder="e.g. Synology DSM NAS" required>
            </div>
            <div>
              <label>Client ID</label>
              <input type="text" id="clientId" placeholder="e.g. homelab-clientid" required>
            </div>
            <div>
              <label>Client Secret</label>
              <div class="input-group">
                <input type="password" id="clientSecret" placeholder="Leave blank to auto-generate, or enter your own" autocomplete="new-password">
                <button type="button" class="icon-btn-action" onclick="generateAndFillSecret('clientSecret')" title="Generate secure 48-char secret">🎲</button>
                <button type="button" class="icon-btn-action" onclick="toggleSecretVisibility('clientSecret')" title="Show/hide secret">👁️</button>
              </div>
            </div>
            <div>
              <label>Upstream Provider</label>
              <select id="clientProvider">
                <option value="google">Google</option>
                <option value="microsoft">Microsoft</option>
                <option value="github">GitHub</option>
                <option value="apple">Apple</option>
              </select>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem; padding-top:1.5rem;">
              <input type="checkbox" id="clientRequirePkce" checked style="width:auto;margin:0;">
              <label for="clientRequirePkce" style="margin:0; font-weight:500;">Require PKCE (S256)</label>
              <span style="font-size:0.75rem; color:#888;">&mdash; uncheck for legacy clients (e.g. Synology)</span>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem; padding-top:1.5rem;">
              <input type="checkbox" id="clientActive" checked style="width:auto;margin:0;">
              <label for="clientActive" style="margin:0; font-weight:500;">Active</label>
              <span style="font-size:0.75rem; color:#888;">&mdash; uncheck to suspend this client without deleting it</span>
            </div>
          </div>
          <div style="margin-top: 1rem;">
            <label>Authorized Redirect URIs (Comma separated)</label>
            <input type="text" id="clientUris" placeholder="e.g. https://dsm.example.com/webman/login.cgi, https://home-example.com/auth/openid/callback" required>
          </div>
          <div class="form-actions">
            <button type="button" class="btn-cancel" id="clientCancelBtn" onclick="resetClientForm()">Cancel</button>
            <button type="submit" class="btn-submit" id="clientSubmitBtn">Save Client Application</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h2>Registered Downstream Applications</h2>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Application / Client ID</th>
                <th>Client Secret</th>
                <th>Provider</th>
                <th>PKCE</th>
                <th>Whitelisted Redirect URIs</th>
                <th>Status</th>
                <th class="actions">Action</th>
              </tr>
            </thead>
            <tbody id="clientTableBody">
              <tr><td colspan="7" class="muted" style="text-align: center;">Loading applications...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- TAB 2: USER MAPPINGS -->
    <div id="tab-users" class="tab-content">
      <div class="card" id="mappingCard">
        <h2 id="mappingFormTitle">Register Identity Mapping</h2>
        <form id="mappingForm">
          <div class="form-grid">
            <div>
              <label>Google Email</label>
              <input type="email" id="userEmail" placeholder="user@gmail.com" required>
            </div>
            <div>
              <label>Target Application Scope</label>
              <select id="userClientId" required>
                <option value="*">All Applications (Global Default *)</option>
              </select>
            </div>
            <div>
              <label>Target Username (Local DSM/HA)</label>
              <input type="text" id="targetUsername" placeholder="e.g. user123" required>
            </div>
            <div>
              <label>Display Name</label>
              <input type="text" id="displayName" placeholder="e.g. John Doe">
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem; padding-top:1.5rem;">
              <input type="checkbox" id="mappingActive" checked style="width:auto;margin:0;">
              <label for="mappingActive" style="margin:0; font-weight:500;">Active</label>
              <span style="font-size:0.75rem; color:#888;">&mdash; uncheck to suspend this user without deleting</span>
            </div>
          </div>
          <div class="form-actions">
            <button type="button" class="btn-cancel" id="mappingCancelBtn" onclick="resetMappingForm()">Cancel</button>
            <button type="submit" class="btn-submit" id="mappingSubmitBtn">Save User Mapping</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h2>Configured User Identity Directory</h2>
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Google Email</th>
                <th>Target App</th>
                <th>Local Target Username</th>
                <th>Display Name</th>
                <th>Status</th>
                <th>Last Login</th>
                <th class="actions">Action</th>
              </tr>
            </thead>
            <tbody id="mappingTableBody">
              <tr><td colspan="7" class="muted" style="text-align: center;">Loading directory...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    const BASE_API = '${adminBasePath}/api';
    let loadedClients = [];
    let originalEditScope = null;

    async function loadData() {
      try {
        const res = await fetch(BASE_API + '/data');
        if (!res.ok) return;
        const data = await res.json();
        loadedClients = data.clients || [];

        document.getElementById('tabBtnClients').innerText = 'Client Applications (' + loadedClients.length + ')';
        document.getElementById('tabBtnUsers').innerText = 'User Mappings (' + (data.mappings || []).length + ')';

        const select = document.getElementById('userClientId');
        const currentVal = select.value;
        select.innerHTML = '<option value="*">All Applications (Global Default *)</option>' +
          loadedClients.map(c => '<option value="' + c.client_id + '">' + (c.client_name || c.name || c.client_id) + ' (' + c.client_id + ')</option>').join('');
        select.value = currentVal || '*';

        renderClients(loadedClients);
        renderMappings(data.mappings || []);
      } catch (err) {
        console.error('Failed to load data', err);
      }
    }

    function renderClients(clients) {
      const tbody = document.getElementById('clientTableBody');
      if (!clients.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted" style="text-align: center;">No client applications registered.</td></tr>';
        return;
      }
      tbody.innerHTML = clients.map((c, idx) => {
        const uris = (c.redirect_uris || []).map(u => '<div class="mono small break-all">' + u + '</div>').join('');
        const encodedSecret = encodeURIComponent(c.client_secret || '');
        const clientJson = encodeURIComponent(JSON.stringify(c));
        return '<tr>' +
          '<td><strong>' + (c.client_name || c.name || c.client_id) + '</strong><br><span class="mono small muted">' + c.client_id + '</span></td>' +
          '<td>' + (c.client_secret
            ? '<div class="secret-cell"><span class="mono small" id="sec-' + idx + '">••••••••••••</span>'
              + '<button class="icon-btn" title="Toggle" onclick="toggleSec(' + idx + ',\\\'' + encodedSecret + '\\\')">&#128065;</button>'
              + '<button class="icon-btn" title="Copy" onclick="copySec(this,\\\'' + encodedSecret + '\\\')">&#128203;</button></div>'
            : '<span class="muted small">None (Public)</span>') + '</td>' +
          '<td><span class="badge app">' + (c.provider || 'google') + '</span></td>' +
          '<td>' + (c.require_pkce !== 0 ? '<span class="badge pkce">S256</span>' : '<span class="badge pkce-off">exempt</span>') + '</td>' +
          '<td>' + uris + '</td>' +
          '<td><span class="badge ' + (c.is_active ? 'active' : 'inactive') + '">' + (c.is_active ? 'ACTIVE' : 'DISABLED') + '</span></td>' +
          '<td class="actions">' +
            '<button class="btn-edit" onclick="editClient(\\\'' + clientJson + '\\\')">Edit</button>' +
            '<button class="btn-del" onclick="deleteClient(\\\'' + c.client_id + '\\\')">Delete</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function renderMappings(mappings) {
      const tbody = document.getElementById('mappingTableBody');
      if (!mappings.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted" style="text-align: center;">No user mappings configured.</td></tr>';
        return;
      }
      tbody.innerHTML = mappings.map(m => {
        const mappingJson = encodeURIComponent(JSON.stringify(m));
        const appBadge = (m.client_id === '*' || !m.client_id)
          ? '<span class="badge global">ALL APPS (*)</span>'
          : '<span class="badge app">' + m.client_id + '</span>';
        return '<tr>' +
          '<td class="mono"><strong>' + m.email + '</strong></td>' +
          '<td>' + appBadge + '</td>' +
          '<td><span class="badge user">' + m.username + '</span></td>' +
          '<td>' + (m.display_name || '-') + '</td>' +
          '<td><span class="badge ' + (m.is_active ? 'active' : 'inactive') + '">' + (m.is_active ? 'ACTIVE' : 'DISABLED') + '</span></td>' +
          '<td><span class="muted small">' + (m.last_login || 'Never') + '</span></td>' +
          '<td class="actions">' +
            '<button class="btn-edit" onclick="editMapping(\\\'' + mappingJson + '\\\')">Edit</button>' +
            '<button class="btn-del" onclick="deleteMapping(\\\'' + encodeURIComponent(m.email) + '\\\', \\\'' + encodeURIComponent(m.client_id || '*') + '\\\')">Delete</button>' +
          '</td>' +
        '</tr>';
      }).join('');
    }

    function switchTab(tabId, btn) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.getElementById(tabId).classList.add('active');
      btn.classList.add('active');
    }

    function editClient(encodedJson) {
      const c = JSON.parse(decodeURIComponent(encodedJson));
      document.getElementById('clientName').value = c.client_name || c.name || '';
      document.getElementById('clientId').value = c.client_id;
      document.getElementById('clientId').disabled = true;
      document.getElementById('clientSecret').value = c.client_secret || '';
      document.getElementById('clientUris').value = (c.redirect_uris || []).join(', ');
      document.getElementById('clientProvider').value = c.provider || 'google';
      document.getElementById('clientRequirePkce').checked = c.require_pkce !== 0;
      document.getElementById('clientActive').checked = c.is_active !== 0;

      document.getElementById('clientFormTitle').innerText = 'Edit Application: ' + c.client_id;
      document.getElementById('clientSubmitBtn').innerText = 'Update Application';
      document.getElementById('clientCancelBtn').style.display = 'inline-block';
      document.getElementById('clientCard').scrollIntoView({ behavior: 'smooth' });
    }

    function resetClientForm() {
      document.getElementById('clientForm').reset();
      document.getElementById('clientId').disabled = false;
      document.getElementById('clientProvider').value = 'google';
      document.getElementById('clientRequirePkce').checked = true;
      document.getElementById('clientActive').checked = true;
      document.getElementById('clientFormTitle').innerText = 'Register Downstream Client Application';
      document.getElementById('clientSubmitBtn').innerText = 'Save Client Application';
      document.getElementById('clientCancelBtn').style.display = 'none';
    }

    document.getElementById('clientForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const uris = document.getElementById('clientUris').value.split(',').map(u => u.trim()).filter(Boolean);
      const payload = {
        client_name: document.getElementById('clientName').value.trim(),
        client_id: document.getElementById('clientId').value.trim(),
        client_secret: document.getElementById('clientSecret').value.trim(),
        provider: document.getElementById('clientProvider').value,
        require_pkce: document.getElementById('clientRequirePkce').checked ? 1 : 0,
        redirect_uris: uris,
        is_active: document.getElementById('clientActive').checked ? 1 : 0
      };
      const res = await fetch(BASE_API + '/clients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) { resetClientForm(); loadData(); }
      else {
        const err = await res.json();
        alert('Failed to save client application: ' + (err.error_description || res.statusText));
      }
    });

    async function deleteClient(clientId) {
      if (!confirm('Delete application ' + clientId + '?')) return;
      const res = await fetch(BASE_API + '/clients/' + encodeURIComponent(clientId), { method: 'DELETE' });
      if (res.ok) loadData();
      else alert('Failed to delete application');
    }

    function editMapping(encodedJson) {
      const m = JSON.parse(decodeURIComponent(encodedJson));
      document.getElementById('userEmail').value = m.email;
      document.getElementById('userEmail').disabled = true;
      document.getElementById('userClientId').value = m.client_id || '*';
      originalEditScope = m.client_id || '*';
      document.getElementById('targetUsername').value = m.username;
      document.getElementById('displayName').value = m.display_name || '';
      document.getElementById('mappingActive').checked = m.is_active !== 0;

      document.getElementById('mappingFormTitle').innerText = 'Edit Mapping for ' + m.email;
      document.getElementById('mappingSubmitBtn').innerText = 'Update User Mapping';
      document.getElementById('mappingCancelBtn').style.display = 'inline-block';
      document.getElementById('mappingCard').scrollIntoView({ behavior: 'smooth' });
    }

    function resetMappingForm() {
      document.getElementById('mappingForm').reset();
      document.getElementById('userEmail').disabled = false;
      document.getElementById('userClientId').value = '*';
      originalEditScope = null;
      document.getElementById('mappingFormTitle').innerText = 'Register Identity Mapping';
      document.getElementById('mappingSubmitBtn').innerText = 'Save User Mapping';
      document.getElementById('mappingCancelBtn').style.display = 'none';
    }

    document.getElementById('mappingForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        email: document.getElementById('userEmail').value.trim(),
        client_id: document.getElementById('userClientId').value,
        original_client_id: originalEditScope,
        username: document.getElementById('targetUsername').value.trim(),
        display_name: document.getElementById('displayName').value.trim(),
        is_active: document.getElementById('mappingActive').checked ? 1 : 0
      };
      const res = await fetch(BASE_API + '/mappings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) { resetMappingForm(); loadData(); }
      else alert('Failed to save user mapping');
    });

    async function deleteMapping(encodedEmail, encodedClientId) {
      if (!confirm('Remove mapping?')) return;
      const res = await fetch(BASE_API + '/mappings/' + encodedEmail + '/' + encodedClientId, { method: 'DELETE' });
      if (res.ok) loadData();
      else alert('Failed to delete mapping');
    }

    const _secVis = {};
    function toggleSec(idx, enc) {
      const span = document.getElementById('sec-' + idx);
      if (!span) return;
      _secVis[idx] = !_secVis[idx];
      span.textContent = _secVis[idx] ? decodeURIComponent(enc) : '••••••••••••';
    }
    function copySec(btn, enc) {
      navigator.clipboard.writeText(decodeURIComponent(enc)).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '&#10003;';
        setTimeout(() => btn.innerHTML = orig, 1500);
      }).catch(() => alert('Copy failed'));
    }

    async function loadProviders() {
      try {
        const res = await fetch(BASE_API + '/providers');
        if (!res.ok) return;
        const providers = await res.json();
        const select = document.getElementById('clientProvider');
        Array.from(select.options).forEach(opt => {
          const p = providers.find(p => p.id === opt.value);
          if (p && !p.isReady) {
            opt.disabled = true;
            opt.text = p.label + ' (not configured)';
            opt.title = 'Set UPSTREAM_' + p.id.toUpperCase() + '_CLIENT_ID and UPSTREAM_' + p.id.toUpperCase() + '_CLIENT_SECRET in wrangler secrets';
          }
        });
        const firstReady = providers.find(p => p.isReady);
        if (firstReady) select.value = firstReady.id;
      } catch (e) { console.warn('Could not load providers', e); }
    }

    function generateClientSecret(length = 48) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
      const randomValues = new Uint8Array(length);
      crypto.getRandomValues(randomValues);
      
      let secret = '';
      for (let i = 0; i < length; i++) {
        secret += chars[randomValues[i] % chars.length];
      }
      return secret;
    }

    function generateAndFillSecret(inputId) {
      const input = document.getElementById(inputId);
      if (input) {
        input.value = generateClientSecret(48);
        input.type = 'text';
        
        setTimeout(() => {
          if (input.type === 'text') {
            input.type = 'password';
          }
        }, 5000);
      }
    }

    function toggleSecretVisibility(inputId) {
      const input = document.getElementById(inputId);
      if (input) {
        input.type = input.type === 'password' ? 'text' : 'password';
      }
    }

    loadProviders();
    loadData();
  </script>

  <footer style="
    margin-top: 3rem;
    padding: 1.5rem 0;
    border-top: 1px solid #1e293b;
    text-align: center;
    font-size: 0.875rem;
    color: #94a3b8;
  ">
    <div>
      © ${new Date().getFullYear()} OIDC Broker Powered by Cloudflare Workers · OAuth 2.1 Compliant · Made with 🔐 by <a href="https://zubir.tech" target="_blank" rel="noopener" style="color: #38bdf8; text-decoration: none;">Zubir Jamal</a>
    </div>
  </footer>
</body>
</html>`;
}
/*
  App do Painel do Lab DC
  - Navegação simples
  - IPAM local (localStorage)
  - Exportação/Importação CSV
  - Stub de integração com vSphere via proxy
*/

(function () {
  'use strict';

  const STORAGE_KEY = 'ipamDataV1';
  const CFG_KEY = 'labCfgV1';

  const elements = {
    navLinks: document.querySelectorAll('.top-nav a'),
    sections: document.querySelectorAll('.page-section'),
    goToIpam: document.getElementById('go-to-ipam'),
    statFree: document.getElementById('stat-free'),
    statUsed: document.getElementById('stat-used'),
    statReserved: document.getElementById('stat-reserved'),
    btnSyncVsphere: document.getElementById('btn-sync-vsphere'),

    // IPAM
    formSubnet: document.getElementById('form-subnet'),
    inputCidr: document.getElementById('input-cidr'),
    inputVlan: document.getElementById('input-vlan'),
    inputDesc: document.getElementById('input-desc'),
    btnExport: document.getElementById('btn-export'),
    btnClear: document.getElementById('btn-clear'),
    fileImport: document.getElementById('file-import'),
    subnetsContainer: document.getElementById('subnets-container'),
    filterStatus: document.getElementById('filter-status'),
    filterSearch: document.getElementById('filter-search'),

    // Config Ajuda
    formConfig: document.getElementById('form-config'),
    cfgProxy: document.getElementById('cfg-proxy'),
    cfgToken: document.getElementById('cfg-token'),
  };

  const STATUS = ['Livre', 'Em uso', 'Reservado'];

  function loadState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { subnets: [] };
      const parsed = JSON.parse(raw);
      if (!parsed.subnets) parsed.subnets = [];
      return parsed;
    } catch (e) {
      console.error('Falha ao carregar estado', e);
      return { subnets: [] };
    }
  }

  function saveState(state) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    updateHomeStats(state);
  }

  function loadConfig() {
    try {
      const raw = localStorage.getItem(CFG_KEY);
      if (!raw) return { proxyBase: '', token: '' };
      const parsed = JSON.parse(raw);
      return { proxyBase: parsed.proxyBase || '', token: parsed.token || '' };
    } catch (e) {
      return { proxyBase: '', token: '' };
    }
  }

  function saveConfig(cfg) {
    localStorage.setItem(CFG_KEY, JSON.stringify(cfg));
  }

  let state = loadState();
  let config = loadConfig();

  // Navegação
  elements.navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const target = link.getAttribute('data-target');
      elements.navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      elements.sections.forEach(sec => {
        sec.classList.toggle('active', sec.id === target);
      });
    });
  });

  if (elements.goToIpam) {
    elements.goToIpam.addEventListener('click', () => {
      document.querySelector('.top-nav a[data-target="ipam"]').click();
    });
  }

  // Helpers IP
  function ipToInt(ip) {
    return ip.split('.').reduce((acc, part) => ((acc << 8) + (parseInt(part, 10) || 0)) >>> 0, 0);
  }
  function intToIp(int) {
    return [24, 16, 8, 0].map(shift => (int >>> shift) & 255).join('.');
  }
  function maskFromBits(bits) {
    return bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  }
  function parseCidr(cidr) {
    const [ip, bitsStr] = (cidr || '').split('/');
    const bits = parseInt(bitsStr, 10);
    if (!ip || isNaN(bits) || bits < 0 || bits > 32) throw new Error('CIDR inválido');
    const ipInt = ipToInt(ip);
    const mask = maskFromBits(bits);
    const network = ipInt & mask;
    const broadcast = network | (~mask >>> 0);
    const hostCount = bits >= 31 ? 0 : (broadcast - network - 1);
    return { ip, bits, ipInt, mask, network, broadcast, hostCount };
  }

  function generateHosts(cidr) {
    const { bits, network, broadcast, hostCount } = parseCidr(cidr);
    if (bits > 30) return [];
    if (hostCount > 1024) {
      alert('Sub-rede muito grande (>1024 hosts). Use um prefixo menor ou importe em CSV.');
      return [];
    }
    const hosts = [];
    for (let ipInt = network + 1; ipInt < broadcast; ipInt++) {
      hosts.push(intToIp(ipInt));
    }
    return hosts;
  }

  function createSubnet({ cidr, vlan = '', description = '' }) {
    const hosts = generateHosts(cidr);
    return {
      id: `${cidr}-${Date.now()}`,
      cidr,
      vlan,
      description,
      ips: hosts.map(ip => ({ ip, status: 'Livre', hostname: '', mac: '', owner: '', notes: '' }))
    };
  }

  function renderIpam() {
    const container = elements.subnetsContainer;
    if (!container) return;
    container.innerHTML = '';

    const filterStatus = elements.filterStatus?.value || 'all';
    const search = (elements.filterSearch?.value || '').toLowerCase().trim();

    for (const subnet of state.subnets) {
      const card = document.createElement('div');
      card.className = 'subnet-card';
      const usedCount = subnet.ips.filter(i => i.status === 'Em uso').length;
      const reservedCount = subnet.ips.filter(i => i.status === 'Reservado').length;
      const freeCount = subnet.ips.filter(i => i.status === 'Livre').length;

      card.innerHTML = `
        <header>
          <h4>${subnet.cidr} ${subnet.vlan ? `<span class="tag">VLAN ${subnet.vlan}</span>` : ''}</h4>
          <div class="controls">
            <span class="muted">${freeCount} livres · ${usedCount} uso · ${reservedCount} reserv.</span>
            <button data-action="delete-subnet" data-id="${subnet.id}" class="danger">Excluir</button>
          </div>
        </header>
        <div class="content">
          <p class="muted">${subnet.description || ''}</p>
          <div class="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hostname</th>
                  <th>MAC</th>
                  <th>Dono</th>
                  <th>Status</th>
                  <th>Notas</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody></tbody>
            </table>
          </div>
        </div>
      `;

      const tbody = card.querySelector('tbody');
      const filtered = subnet.ips.filter(row => {
        const matchesStatus = filterStatus === 'all' || row.status === filterStatus;
        const hay = `${row.ip} ${row.hostname} ${row.mac} ${row.owner} ${row.notes}`.toLowerCase();
        const matchesSearch = !search || hay.includes(search);
        return matchesStatus && matchesSearch;
      });

      for (const row of filtered) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${row.ip}</td>
          <td><input class="w-compact" data-field="hostname" value="${escapeHtml(row.hostname)}" /></td>
          <td><input class="w-compact" data-field="mac" value="${escapeHtml(row.macs || row.mac || '')}" /></td>
          <td><input class="w-compact" data-field="owner" value="${escapeHtml(row.owner)}" /></td>
          <td>
            <select data-field="status">
              ${STATUS.map(s => `<option value="${s}" ${row.status === s ? 'selected' : ''}>${s}</option>`).join('')}
            </select>
          </td>
          <td><input class="w-compact" data-field="notes" value="${escapeHtml(row.notes)}" /></td>
          <td class="table-actions">
            <button data-action="clear" title="Limpar">Limpar</button>
            <button data-action="delete" class="danger" title="Excluir">Excluir</button>
          </td>
        `;

        // Eventos de edição
        tr.querySelectorAll('input, select').forEach(input => {
          input.addEventListener('change', (e) => {
            const field = input.getAttribute('data-field');
            const value = input.tagName === 'SELECT' ? input.value : input.value || '';
            row[field] = value;
            saveState(state);
            updateHomeStats(state);
          });
        });

        tr.querySelector('[data-action="clear"]').addEventListener('click', () => {
          row.hostname = '';
          row.mac = '';
          row.owner = '';
          row.notes = '';
          row.status = 'Livre';
          saveState(state);
          renderIpam();
        });
        tr.querySelector('[data-action="delete"]').addEventListener('click', () => {
          subnet.ips = subnet.ips.filter(r => r.ip !== row.ip);
          saveState(state);
          renderIpam();
        });

        tbody.appendChild(tr);
      }

      card.querySelector('[data-action="delete-subnet"]').addEventListener('click', () => {
        if (!confirm(`Excluir sub-rede ${subnet.cidr}?`)) return;
        state.subnets = state.subnets.filter(s => s.id !== subnet.id);
        saveState(state);
        renderIpam();
      });

      elements.subnetsContainer.appendChild(card);
    }
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>"]+/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  // Home stats
  function updateHomeStats(cur) {
    try {
      const allIps = cur.subnets.flatMap(s => s.ips);
      const free = allIps.filter(i => i.status === 'Livre').length;
      const used = allIps.filter(i => i.status === 'Em uso').length;
      const reserved = allIps.filter(i => i.status === 'Reservado').length;
      if (elements.statFree) elements.statFree.textContent = String(free);
      if (elements.statUsed) elements.statUsed.textContent = String(used);
      if (elements.statReserved) elements.statReserved.textContent = String(reserved);
    } catch (e) {}
  }

  // Eventos IPAM
  if (elements.formSubnet) {
    elements.formSubnet.addEventListener('submit', (e) => {
      e.preventDefault();
      const cidr = elements.inputCidr.value.trim();
      if (!cidr) return;
      try {
        parseCidr(cidr); // valida
      } catch (err) {
        alert('CIDR inválido. Ex.: 192.168.10.0/24');
        return;
      }
      const subnet = createSubnet({
        cidr,
        vlan: elements.inputVlan.value.trim(),
        description: elements.inputDesc.value.trim()
      });
      state.subnets.push(subnet);
      saveState(state);
      elements.inputCidr.value = '';
      elements.inputVlan.value = '';
      elements.inputDesc.value = '';
      renderIpam();
    });
  }

  if (elements.btnClear) {
    elements.btnClear.addEventListener('click', () => {
      if (!confirm('Limpar todos os dados do IPAM?')) return;
      state = { subnets: [] };
      saveState(state);
      renderIpam();
    });
  }

  if (elements.btnExport) {
    elements.btnExport.addEventListener('click', () => {
      const rows = [['subnet', 'vlan', 'ip', 'status', 'hostname', 'mac', 'owner', 'notes']];
      for (const s of state.subnets) {
        for (const r of s.ips) {
          rows.push([s.cidr, s.vlan || '', r.ip, r.status, r.hostname || '', r.mac || '', r.owner || '', r.notes || '']);
        }
      }
      const csv = rows.map(row => row.map(v => csvEscape(v)).join(',')).join('\n');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ipam.csv';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });
  }

  if (elements.fileImport) {
    elements.fileImport.addEventListener('change', async () => {
      const file = elements.fileImport.files?.[0];
      if (!file) return;
      const text = await file.text();
      importCsv(text);
      elements.fileImport.value = '';
    });
  }

  if (elements.filterStatus) {
    elements.filterStatus.addEventListener('change', renderIpam);
  }
  if (elements.filterSearch) {
    elements.filterSearch.addEventListener('input', renderIpam);
  }

  // Config
  if (elements.formConfig) {
    // Preenche
    if (elements.cfgProxy) elements.cfgProxy.value = config.proxyBase || '';
    if (elements.cfgToken) elements.cfgToken.value = config.token || '';

    elements.formConfig.addEventListener('submit', (e) => {
      e.preventDefault();
      config = {
        proxyBase: (elements.cfgProxy?.value || '').trim(),
        token: (elements.cfgToken?.value || '').trim(),
      };
      saveConfig(config);
      alert('Configuração salva.');
    });
  }

  // vSphere sync (stub)
  if (elements.btnSyncVsphere) {
    elements.btnSyncVsphere.addEventListener('click', async () => {
      if (!config.proxyBase) {
        alert('Configure a Base URL do Proxy/API na aba Ajuda.');
        return;
      }
      try {
        elements.btnSyncVsphere.disabled = true;
        elements.btnSyncVsphere.textContent = 'Sincronizando...';
        const headers = { 'Accept': 'application/json' };
        if (config.token) headers['Authorization'] = config.token.startsWith('Bearer') ? config.token : `Bearer ${config.token}`;
        const res = await fetch(smartJoin(config.proxyBase, '/vsphere/vms'), { headers });
        if (!res.ok) throw new Error('Falha ao obter VMs');
        const vms = await res.json();
        let updated = 0;
        for (const vm of vms) {
          const ips = Array.isArray(vm.ipAddresses) ? vm.ipAddresses : [];
          const macs = Array.isArray(vm.macs) ? vm.macs : [];
          for (const ip of ips) {
            // Procura IP no IPAM
            for (const s of state.subnets) {
              const found = s.ips.find(i => i.ip === ip);
              if (found) {
                found.status = 'Em uso';
                if (!found.hostname) found.hostname = vm.name || '';
                if (!found.mac && macs[0]) found.mac = macs[0];
                updated++;
              }
            }
          }
        }
        saveState(state);
        renderIpam();
        alert(`Sincronização concluída. IPs atualizados: ${updated}`);
      } catch (err) {
        console.error(err);
        alert('Erro na sincronização. Verifique o proxy/API.');
      } finally {
        elements.btnSyncVsphere.disabled = false;
        elements.btnSyncVsphere.textContent = 'Sincronizar vSphere (beta)';
      }
    });
  }

  function smartJoin(base, path) {
    if (!base.endsWith('/') && !path.startsWith('/')) return `${base}/${path}`;
    if (base.endsWith('/') && path.startsWith('/')) return base + path.slice(1);
    return base + path;
  }

  function csvEscape(value) {
    const s = String(value ?? '');
    if (/[",\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  }

  function importCsv(text) {
    const lines = text.split(/\r?\n/).filter(l => l.trim().length);
    if (lines.length < 2) return;
    const header = lines[0].split(',').map(h => h.trim());
    const idx = Object.fromEntries(header.map((h, i) => [h.toLowerCase(), i]));
    const required = ['subnet', 'ip'];
    for (const r of required) {
      if (!(r in idx)) { alert('CSV inválido. Cabeçalhos necessários: subnet, ip'); return; }
    }
    const bySubnet = new Map();
    for (let i = 1; i < lines.length; i++) {
      const cols = parseCsvLine(lines[i]);
      if (!cols.length) continue;
      const subnet = cols[idx['subnet']].trim();
      const ip = cols[idx['ip']].trim();
      if (!subnet || !ip) continue;
      if (!bySubnet.has(subnet)) bySubnet.set(subnet, []);
      bySubnet.get(subnet).push({
        ip,
        status: safeCol(cols, idx['status']) || 'Livre',
        hostname: safeCol(cols, idx['hostname']) || '',
        mac: safeCol(cols, idx['mac']) || '',
        owner: safeCol(cols, idx['owner']) || '',
        notes: safeCol(cols, idx['notes']) || ''
      });
    }

    for (const [cidr, rows] of bySubnet.entries()) {
      let subnet = state.subnets.find(s => s.cidr === cidr);
      if (!subnet) {
        subnet = { id: `${cidr}-${Date.now()}`, cidr, vlan: '', description: '', ips: [] };
        state.subnets.push(subnet);
      }
      const map = new Map(subnet.ips.map(r => [r.ip, r]));
      for (const r of rows) {
        if (map.has(r.ip)) {
          const cur = map.get(r.ip);
          cur.status = r.status;
          cur.hostname = r.hostname;
          cur.mac = r.mac;
          cur.owner = r.owner;
          cur.notes = r.notes;
        } else {
          subnet.ips.push({ ip: r.ip, status: r.status, hostname: r.hostname, mac: r.mac, owner: r.owner, notes: r.notes });
        }
      }
    }

    saveState(state);
    renderIpam();
  }

  function safeCol(cols, idx) {
    return typeof idx === 'number' ? cols[idx] : '';
  }

  function parseCsvLine(line) {
    const result = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (inQuotes) {
        if (ch === '"') {
          if (line[i + 1] === '"') { cur += '"'; i++; }
          else { inQuotes = false; }
        } else {
          cur += ch;
        }
      } else {
        if (ch === ',') { result.push(cur); cur = ''; }
        else if (ch === '"') { inQuotes = true; }
        else { cur += ch; }
      }
    }
    result.push(cur);
    return result.map(s => s.trim());
  }

  // Inicialização
  updateHomeStats(state);
  renderIpam();
})();


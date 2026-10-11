// Nova Proxy Admin - Frontend Controller (No Emojis, Complete User Management & RBAC)
document.addEventListener('DOMContentLoaded', () => {
  // -----------------------------------------------------
  // State
  // -----------------------------------------------------
  let hostsData = [];
  let ufwRulesData = [];
  let certsData = [];
  let usersData = [];
  let currentFilter = 'all';
  let activeTab = 'tab-hosts';
  let activeRole = localStorage.getItem('nova_role') || 'super_admin';

  // -----------------------------------------------------
  // User Authentication & 10-Minute Inactivity Auto-Logout
  // -----------------------------------------------------
  const sessionToken = localStorage.getItem('nova_session_token') || localStorage.getItem('nova_token');
  const INACTIVITY_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes (600 seconds)
  let lastUserActivity = Date.now();

  async function verifySession() {
    if (!sessionToken) {
      window.location.href = '/login?require_auth=1';
      return;
    }

    try {
      const res = await fetch('/api/auth/me', {
        headers: {
          'Authorization': `Bearer ${sessionToken}`
        }
      });
      if (!res.ok) {
        localStorage.removeItem('nova_session_token');
        localStorage.removeItem('nova_current_user');
        window.location.href = '/login?session_expired=1';
        return;
      }
      const data = await res.json();
      if (data && data.user) {
        activeRole = data.user.role || 'super_admin';
        localStorage.setItem('nova_role', activeRole);
        localStorage.setItem('nova_current_user', JSON.stringify(data.user));

        const navUserDisplay = document.getElementById('nav-username-display');
        const navRoleDisplay = document.getElementById('nav-userrole-display');
        if (navUserDisplay) navUserDisplay.textContent = data.user.full_name || data.user.username;
        if (navRoleDisplay) navRoleDisplay.textContent = getRoleTitle(data.user.role);

        applyRolePermissions(activeRole);
      }
    } catch (err) {
      console.warn('Session verification fallback:', err);
    }
  }

  function registerActivityListeners() {
    const activityEvents = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
    activityEvents.forEach(evt => {
      window.addEventListener(evt, () => {
        lastUserActivity = Date.now();
      }, { passive: true });
    });

    // Check inactivity every 15 seconds
    setInterval(async () => {
      if (Date.now() - lastUserActivity > INACTIVITY_TIMEOUT_MS) {
        await handleLogout(true);
      }
    }, 15000);
  }

  async function handleLogout(isSessionExpired = false) {
    const token = localStorage.getItem('nova_session_token');
    try {
      if (token) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      }
    } catch (e) {}
    localStorage.removeItem('nova_session_token');
    localStorage.removeItem('nova_current_user');
    window.location.href = isSessionExpired ? '/login?session_expired=1' : '/login?logged_out=1';
  }

  const btnLogout = document.getElementById('btn-logout');
  if (btnLogout) {
    btnLogout.addEventListener('click', (e) => {
      e.preventDefault();
      handleLogout(false);
    });
  }

  verifySession();
  registerActivityListeners();

  // -----------------------------------------------------
  // Theme Toggle (Dark / Light) with SVG Icons
  // -----------------------------------------------------
  const htmlEl = document.documentElement;
  const themeToggleBtn = document.getElementById('theme-toggle');
  const themeIcon = document.getElementById('theme-icon');

  const savedTheme = localStorage.getItem('nova_theme') || 'dark';
  setTheme(savedTheme);

  themeToggleBtn.addEventListener('click', () => {
    const current = htmlEl.getAttribute('data-theme') || 'dark';
    const next = current === 'dark' ? 'light' : 'dark';
    setTheme(next);
  });

  function setTheme(t) {
    htmlEl.setAttribute('data-theme', t);
    localStorage.setItem('nova_theme', t);
    if (themeIcon) {
      themeIcon.innerHTML = t === 'dark' 
        ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`
        : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
    }
  }

  // -----------------------------------------------------
  // Toast System (SVG Icons Only)
  // -----------------------------------------------------
  function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let iconSvg = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`;
    if (type === 'error') {
      iconSvg = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`;
    } else if (type === 'warning') {
      iconSvg = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;
    }

    toast.innerHTML = `
      <span style="display: flex; align-items: center;">${iconSvg}</span>
      <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  function escapeHtml(text) {
    if (!text) return '';
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // -----------------------------------------------------
  // Role-Based Access Control (RBAC) System
  // -----------------------------------------------------
  const roleSelect = document.getElementById('active-role-select');
  const roleAvatar = document.getElementById('role-avatar');
  const roleBanner = document.getElementById('role-notice-banner');
  const roleBannerText = document.getElementById('role-banner-text');

  if (roleSelect) {
    roleSelect.value = activeRole;
    roleSelect.addEventListener('change', (e) => {
      activeRole = e.target.value;
      localStorage.setItem('nova_role', activeRole);
      applyRolePermissions(activeRole);
      renderHostsTable();
      showToast(`Active role switched to: ${getRoleTitle(activeRole)}`, 'warning');
    });
  }
  applyRolePermissions(activeRole);

  function getRoleTitle(role) {
    if (role === 'super_admin') return 'Super Admin';
    if (role === 'webmaster') return 'Webmaster';
    if (role === 'security') return 'Security Analyst';
    if (role === 'billing') return 'Billing Officer';
    return role;
  }

  function applyRolePermissions(role) {
    const btnOpenCreate = document.getElementById('btn-open-create-modal');
    const tabUfwBtn = document.getElementById('tab-btn-ufw');
    const tabSecurityBtn = document.getElementById('tab-btn-security');
    const tabBillingBtn = document.getElementById('tab-btn-billing');
    const tabSuspensionBtn = document.getElementById('tab-btn-suspension');
    const tabUsersBtn = document.getElementById('tab-btn-users');

    if (roleAvatar) {
      roleAvatar.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;
    }

    // Role banner
    roleBanner.style.display = 'block';
    if (role === 'super_admin') {
      roleBanner.style.display = 'none';
    } else if (role === 'webmaster') {
      roleBannerText.textContent = 'Active Role: Webmaster. You can add new domain names, but editing, deleting, and suspending existing domains are disabled.';
    } else if (role === 'security') {
      roleBannerText.textContent = 'Active Role: Security Analyst. You have full access to WHOIS investigation, SSL inspection, Domain Abuse reports, and Audit logs.';
    } else if (role === 'billing') {
      roleBannerText.textContent = 'Active Role: Billing Officer. You have access to Domain & SSL expiration tracking, renewal deadlines, and billing health.';
    }

    // Super Admin only tabs
    if (tabUfwBtn) {
      if (role === 'super_admin') {
        tabUfwBtn.style.display = 'inline-flex';
      } else {
        tabUfwBtn.style.display = 'none';
        if (activeTab === 'tab-ufw') switchTab('tab-hosts');
      }
    }

    if (tabSuspensionBtn) {
      if (role === 'super_admin') {
        tabSuspensionBtn.style.display = 'inline-flex';
      } else {
        tabSuspensionBtn.style.display = 'none';
        if (activeTab === 'tab-suspension') switchTab('tab-hosts');
      }
    }

    if (tabUsersBtn) {
      tabUsersBtn.style.display = 'inline-flex';
    }

    // Export & Import backup controls (Super Admin only)
    const btnExportAll = document.getElementById('btn-export-all-zip');
    const btnOpenMigrate = document.getElementById('btn-open-migrate-modal');
    if (btnExportAll) {
      btnExportAll.style.display = (role === 'super_admin') ? 'inline-flex' : 'none';
    }
    if (btnOpenMigrate) {
      btnOpenMigrate.style.display = (role === 'super_admin') ? 'inline-flex' : 'none';
    }

    // Add Domain button permission
    if (btnOpenCreate) {
      if (role === 'super_admin' || role === 'webmaster') {
        btnOpenCreate.style.display = 'inline-flex';
      } else {
        btnOpenCreate.style.display = 'none';
      }
    }
  }

  // -----------------------------------------------------
  // Tabs Navigation
  // -----------------------------------------------------
  const tabButtons = document.querySelectorAll('.nav-tab-item');
  const tabContents = document.querySelectorAll('.tab-content');

  function switchTab(targetTab) {
    tabButtons.forEach(b => b.classList.remove('active'));
    tabContents.forEach(c => {
      c.style.display = 'none';
      c.classList.remove('active');
    });

    const activeBtn = document.querySelector(`.nav-tab-item[data-tab="${targetTab}"]`);
    if (activeBtn) activeBtn.classList.add('active');

    const targetContent = document.getElementById(targetTab);
    if (targetContent) {
      targetContent.style.display = 'block';
      targetContent.classList.add('active');
    }

    // Only display System Hardware & Live Telemetry on the homepage (tab-hosts)
    const telemetryPanel = document.getElementById('system-telemetry-panel');
    if (telemetryPanel) {
      telemetryPanel.style.display = (targetTab === 'tab-hosts') ? 'block' : 'none';
    }

    activeTab = targetTab;
    if (targetTab === 'tab-hosts') loadHosts();
    if (targetTab === 'tab-ufw') loadUfwRules();
    if (targetTab === 'tab-security') loadAbuseReports();
    if (targetTab === 'tab-billing') loadBillingData();
    if (targetTab === 'tab-suspension') {
      loadSuspensionSettings();
      loadSmtpSettings();
    }
    if (targetTab === 'tab-logs') loadAuditLogs();
    if (targetTab === 'tab-users') loadUsers();
  }

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      if (btn.classList.contains('locked')) return;
      switchTab(targetTab);
    });
  });

  // -----------------------------------------------------
  // System Diagnostics & Stats
  // -----------------------------------------------------
  async function loadSystemStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();

      if (data.stats) {
        document.getElementById('stat-total-hosts').textContent = data.stats.total_hosts ?? 0;
        document.getElementById('stat-active-hosts').textContent = data.stats.active_hosts ?? 0;
        document.getElementById('stat-ufw-rules').textContent = data.stats.ufw_rules_count ?? 0;
        document.getElementById('stat-suspended-hosts').textContent = data.stats.suspended_hosts ?? 0;
      }
    } catch (err) {
      console.error('Failed to load status:', err);
    }
  }

  // -----------------------------------------------------
  // Hardware Telemetry & Real-Time Usage Graph
  // -----------------------------------------------------
  async function loadSystemMetrics() {
    try {
      const res = await fetch('/api/system-metrics');
      if (!res.ok) return;
      const data = await res.json();

      // OS & Host identification
      const navOsBadge = document.getElementById('navbar-os-badge');
      const telemOsText = document.getElementById('telemetry-os-text');
      const telemHostText = document.getElementById('telemetry-hostname-text');

      if (navOsBadge && data.os) navOsBadge.textContent = data.os.name;
      if (telemOsText && data.os) telemOsText.textContent = data.os.name;
      if (telemHostText && data.os) telemHostText.textContent = `Host: ${data.os.hostname || 'localhost'}`;

      // CPU Metrics
      if (data.cpu) {
        const cpuPct = data.cpu.percent ?? 0;
        const cpuValEl = document.getElementById('cpu-current-percent');
        const cpuFillEl = document.getElementById('cpu-progress-fill');
        const cpuCoresEl = document.getElementById('cpu-cores-text');
        const cpuLoadEl = document.getElementById('cpu-load-text');
        const legCpuEl = document.getElementById('graph-legend-cpu');

        if (cpuValEl) cpuValEl.textContent = `${cpuPct.toFixed(1)}%`;
        if (cpuFillEl) cpuFillEl.style.width = `${Math.min(100, Math.max(0, cpuPct))}%`;
        if (cpuCoresEl) cpuCoresEl.textContent = `${data.cpu.logical_cores} Cores (${data.cpu.physical_cores} Physical)`;
        if (cpuLoadEl && Array.isArray(data.cpu.load_avg)) {
          cpuLoadEl.textContent = `Load: ${data.cpu.load_avg.join(', ')}`;
        }
        if (legCpuEl) legCpuEl.textContent = `${cpuPct.toFixed(1)}%`;
      }

      // RAM Metrics
      if (data.ram) {
        const ramPct = data.ram.percent ?? 0;
        const ramValEl = document.getElementById('ram-current-percent');
        const ramFillEl = document.getElementById('ram-progress-fill');
        const ramUsageEl = document.getElementById('ram-usage-text');
        const ramAvailEl = document.getElementById('ram-avail-text');
        const legRamEl = document.getElementById('graph-legend-ram');

        if (ramValEl) ramValEl.textContent = `${ramPct.toFixed(1)}%`;
        if (ramFillEl) ramFillEl.style.width = `${Math.min(100, Math.max(0, ramPct))}%`;
        if (ramUsageEl) ramUsageEl.textContent = `${data.ram.used_gb.toFixed(2)} GB / ${data.ram.total_gb.toFixed(2)} GB`;
        if (ramAvailEl) ramAvailEl.textContent = `${data.ram.available_gb.toFixed(2)} GB Free`;
        if (legRamEl) legRamEl.textContent = `${ramPct.toFixed(1)}%`;
      }

      // Disk Metrics
      if (data.disk) {
        const diskPct = data.disk.percent ?? 0;
        const diskValEl = document.getElementById('disk-current-percent');
        const diskFillEl = document.getElementById('disk-progress-fill');
        const diskUsageEl = document.getElementById('disk-usage-text');

        if (diskValEl) diskValEl.textContent = `${diskPct.toFixed(1)}%`;
        if (diskFillEl) diskFillEl.style.width = `${Math.min(100, Math.max(0, diskPct))}%`;
        if (diskUsageEl) diskUsageEl.textContent = `${data.disk.used_gb.toFixed(1)} GB / ${data.disk.total_gb.toFixed(1)} GB`;
      }

      // Live SVG Graph
      if (Array.isArray(data.history) && data.history.length > 1) {
        lastTelemetryHistory = data.history;
        renderMetricsChart(data.history);
      }
    } catch (err) {
      console.warn('System telemetry polling error:', err);
    }
  }

  let lastTelemetryHistory = [];

  function renderMetricsChart(history) {
    const svg = document.getElementById('metrics-svg');
    if (!svg || !history || history.length < 2) return;

    // Dynamically calculate graph dimensions to fit container perfectly without distortion
    const container = svg.parentElement;
    const containerWidth = container ? container.clientWidth : 800;
    const width = Math.max(500, Math.round(containerWidth || svg.clientWidth || 800));
    const height = 160;
    const padLeft = 48;
    const padRight = 18;
    const padTop = 16;
    const padBottom = 26;
    const plotW = Math.max(100, width - padLeft - padRight);
    const plotH = Math.max(50, height - padTop - padBottom);

    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');

    const n = history.length;
    const xStep = n > 1 ? plotW / (n - 1) : plotW;

    // Build coordinates
    const cpuPoints = [];
    const ramPoints = [];

    history.forEach((pt, i) => {
      const x = padLeft + i * xStep;
      const cVal = Math.min(100, Math.max(0, Number(pt.cpu) || 0));
      const rVal = Math.min(100, Math.max(0, Number(pt.ram) || 0));
      const yCpu = padTop + plotH * (1 - cVal / 100);
      const yRam = padTop + plotH * (1 - rVal / 100);
      cpuPoints.push({ x, y: yCpu, val: cVal, time: pt.time });
      ramPoints.push({ x, y: yRam, val: rVal, time: pt.time });
    });

    const baselineY = padTop + plotH;

    // SVG string construction
    let svgContent = `
      <defs>
        <linearGradient id="chartCpuGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#0284c7" stop-opacity="0.38"/>
          <stop offset="100%" stop-color="#0284c7" stop-opacity="0.0"/>
        </linearGradient>
        <linearGradient id="chartRamGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#10b981" stop-opacity="0.32"/>
          <stop offset="100%" stop-color="#10b981" stop-opacity="0.0"/>
        </linearGradient>
      </defs>
    `;

    // Horizontal grid lines (0%, 25%, 50%, 75%, 100%)
    const gridLevels = [0, 25, 50, 75, 100];
    gridLevels.forEach(pct => {
      const y = padTop + plotH * (1 - pct / 100);
      svgContent += `
        <line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="rgba(148, 163, 184, 0.16)" stroke-dasharray="3 3" stroke-width="1"/>
        <text x="${padLeft - 8}" y="${y + 3.5}" text-anchor="end" fill="#94a3b8" font-size="9.5" font-weight="600" font-family="var(--font-primary)">${pct}%</text>
      `;
    });

    // RAM Area polygon
    const ramPolyPoints = [
      `${padLeft},${baselineY}`,
      ...ramPoints.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`),
      `${ramPoints[n - 1].x.toFixed(1)},${baselineY}`
    ].join(' ');
    svgContent += `<polygon points="${ramPolyPoints}" fill="url(#chartRamGrad)"/>`;

    // CPU Area polygon
    const cpuPolyPoints = [
      `${padLeft},${baselineY}`,
      ...cpuPoints.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`),
      `${cpuPoints[n - 1].x.toFixed(1)},${baselineY}`
    ].join(' ');
    svgContent += `<polygon points="${cpuPolyPoints}" fill="url(#chartCpuGrad)"/>`;

    // RAM Polyline
    const ramLine = ramPoints.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    svgContent += `<polyline points="${ramLine}" fill="none" stroke="#10b981" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>`;

    // CPU Polyline
    const cpuLine = cpuPoints.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
    svgContent += `<polyline points="${cpuLine}" fill="none" stroke="#0284c7" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>`;

    // Latest Markers
    const latestCpu = cpuPoints[n - 1];
    const latestRam = ramPoints[n - 1];
    if (latestRam) {
      svgContent += `
        <circle cx="${latestRam.x.toFixed(1)}" cy="${latestRam.y.toFixed(1)}" r="4" fill="#10b981" stroke="#ffffff" stroke-width="2"/>
      `;
    }
    if (latestCpu) {
      svgContent += `
        <circle cx="${latestCpu.x.toFixed(1)}" cy="${latestCpu.y.toFixed(1)}" r="4" fill="#0284c7" stroke="#ffffff" stroke-width="2"/>
      `;
    }

    // Time Axis Labels (sample 4-5 labels)
    const labelStep = Math.max(1, Math.floor(n / 4));
    for (let i = 0; i < n; i += labelStep) {
      const pt = cpuPoints[i];
      if (pt && pt.time) {
        svgContent += `
          <text x="${pt.x.toFixed(1)}" y="${height - 7}" text-anchor="middle" fill="#94a3b8" font-size="9.5" font-family="var(--font-primary)">${escapeHtml(pt.time)}</text>
        `;
      }
    }
    if ((n - 1) % labelStep !== 0 && cpuPoints[n - 1]) {
      const pt = cpuPoints[n - 1];
      svgContent += `
        <text x="${pt.x.toFixed(1)}" y="${height - 7}" text-anchor="middle" fill="#94a3b8" font-size="9.5" font-family="var(--font-primary)">${escapeHtml(pt.time)}</text>
      `;
    }

    svg.innerHTML = svgContent;
  }

  window.addEventListener('resize', () => {
    if (lastTelemetryHistory && lastTelemetryHistory.length > 1) {
      renderMetricsChart(lastTelemetryHistory);
    }
  });

  // -----------------------------------------------------
  // Reusable Pagination Engine (10 Records Per Page)
  // -----------------------------------------------------
  function renderPagination(container, currentPage, totalPages, totalItems, startIndex, pageItemCount, onPageChange) {
    if (!container) return;
    if (totalItems === 0) {
      container.style.display = 'none';
      return;
    }

    container.style.display = 'flex';
    const from = startIndex + 1;
    const to = startIndex + pageItemCount;

    let buttonsHtml = `
      <button class="pagination-btn" ${currentPage <= 1 ? 'disabled' : ''} data-page="${currentPage - 1}">
        Previous
      </button>
    `;

    for (let p = 1; p <= totalPages; p++) {
      if (totalPages <= 7 || p === 1 || p === totalPages || Math.abs(p - currentPage) <= 1) {
        buttonsHtml += `
          <button class="pagination-btn ${p === currentPage ? 'active' : ''}" data-page="${p}">
            ${p}
          </button>
        `;
      } else if (p === 2 && currentPage > 3) {
        buttonsHtml += `<span style="padding: 0 0.25rem; color: var(--text-muted); line-height: 30px;">&hellip;</span>`;
      } else if (p === totalPages - 1 && currentPage < totalPages - 2) {
        buttonsHtml += `<span style="padding: 0 0.25rem; color: var(--text-muted); line-height: 30px;">&hellip;</span>`;
      }
    }

    buttonsHtml += `
      <button class="pagination-btn" ${currentPage >= totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">
        Next
      </button>
    `;

    container.innerHTML = `
      <div class="pagination-info">Showing ${from}&ndash;${to} of ${totalItems} records (10 per page)</div>
      <div class="pagination-controls">${buttonsHtml}</div>
    `;

    container.querySelectorAll('.pagination-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetPage = parseInt(btn.getAttribute('data-page'), 10);
        if (targetPage && targetPage !== currentPage && targetPage >= 1 && targetPage <= totalPages) {
          onPageChange(targetPage);
        }
      });
    });
  }

  // -----------------------------------------------------
  // Proxy Hosts Management (10 Records Per Page)
  // -----------------------------------------------------
  let hostsCurrentPage = 1;
  const HOSTS_PER_PAGE = 10;

  async function loadHosts() {
    try {
      const res = await fetch('/api/hosts');
      hostsData = await res.json();
      renderHostsTable();
      loadSystemStatus();
    } catch (err) {
      showToast('Error loading proxy hosts', 'error');
    }
  }

  function renderHostsTable() {
    const tbody = document.getElementById('hosts-table-body');
    const paginationEl = document.getElementById('hosts-pagination');
    const query = (document.getElementById('host-search-input').value || '').toLowerCase().trim();

    const filtered = hostsData.filter(h => {
      const matchesSearch = !query || 
        h.domain_names.toLowerCase().includes(query) ||
        h.forward_host.toLowerCase().includes(query) ||
        String(h.forward_port).includes(query);

      let matchesFilter = true;
      if (currentFilter === 'active') matchesFilter = !h.is_suspended;
      if (currentFilter === 'suspended') matchesFilter = h.is_suspended;
      if (currentFilter === 'ssl') matchesFilter = h.ssl_forced;

      return matchesSearch && matchesFilter;
    });

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">
            No reverse proxy hosts match the filter criteria.
          </td>
        </tr>
      `;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(filtered.length / HOSTS_PER_PAGE);
    if (hostsCurrentPage > totalPages) hostsCurrentPage = totalPages;
    if (hostsCurrentPage < 1) hostsCurrentPage = 1;

    const startIndex = (hostsCurrentPage - 1) * HOSTS_PER_PAGE;
    const pageItems = filtered.slice(startIndex, startIndex + HOSTS_PER_PAGE);

    tbody.innerHTML = pageItems.map(h => {
      const domainList = h.domain_names.split(',').map(d => d.trim());
      const primaryDomain = domainList[0];
      const aliases = domainList.slice(1);

      let sslBadgeClass = 'none';
      let sslBadgeText = 'No SSL';
      if (h.ssl_forced) {
        sslBadgeClass = h.ssl_status === 'expiring_soon' ? 'expiring' : 'valid';
        sslBadgeText = h.ssl_status === 'expiring_soon' ? 'Expiring Soon' : "Let's Encrypt";
      }

      const canEdit = activeRole === 'super_admin';
      const canSuspend = activeRole === 'super_admin';
      const canDelete = activeRole === 'super_admin';
      const canExport = activeRole === 'super_admin';

      return `
        <tr>
          <td>
            <div class="domain-cell">
              <span class="domain-name">
                <a href="${h.is_suspended ? `/suspended?domain=${encodeURIComponent(primaryDomain)}&reason=${encodeURIComponent(h.suspended_reason || 'Administrative Maintenance')}` : (h.ssl_forced ? 'https' : 'http') + '://' + primaryDomain}" target="_blank" rel="noreferrer" style="color: inherit; text-decoration: underline dotted;" title="${h.is_suspended ? 'View public suspended landing page' : 'Visit live site'}">
                  ${escapeHtml(primaryDomain)}
                </a>
              </span>
              ${aliases.length > 0 ? `<span class="domain-aliases">+${aliases.length} (${escapeHtml(aliases.join(', '))})</span>` : ''}
              ${h.is_suspended ? `<span style="font-size: 0.72rem; color: #f59e0b; margin-top: 0.2rem;">Suspension: ${escapeHtml(h.suspended_reason || 'Policy')}</span>` : ''}
            </div>
          </td>
          <td>
            <span class="target-badge">
              <span style="color: var(--secondary);">${escapeHtml(h.forward_scheme)}://</span>${escapeHtml(h.forward_host)}:${h.forward_port}
            </span>
          </td>
          <td>
            <div style="display: flex; gap: 0.35rem; flex-wrap: wrap; align-items: center;">
              <span class="badge-tag" style="background: rgba(99, 102, 241, 0.12); color: #818cf8; font-size: 0.72rem; padding: 0.2rem 0.5rem; border-radius: 5px; font-weight: 700;" title="Configured Application Name">${escapeHtml(h.app_name || 'Web App')}</span>
              ${h.websocket_support ? `<span class="badge-tag" style="background: rgba(2, 132, 199, 0.1); color: var(--secondary); font-size: 0.7rem; padding: 0.15rem 0.45rem; border-radius: 5px; font-weight: 700;">WS</span>` : ''}
              ${h.block_exploits ? `<span class="badge-tag" style="background: rgba(16, 185, 129, 0.1); color: var(--accent-emerald); font-size: 0.7rem; padding: 0.15rem 0.45rem; border-radius: 5px; font-weight: 700;">WAF</span>` : ''}
            </div>
          </td>
          <td>
            <span class="ssl-badge ${sslBadgeClass}">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              ${sslBadgeText}
            </span>
          </td>
          <td>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <label class="switch ${!canSuspend ? 'disabled' : ''}" title="${canSuspend ? 'Toggle active / suspended mode' : 'Role restricted: Only Super Admin can suspend domains'}">
                <input type="checkbox" ${h.is_suspended ? '' : 'checked'} ${!canSuspend ? 'disabled' : ''} onchange="toggleHostSuspension(${h.id})">
                <span class="slider"></span>
              </label>
              <span style="font-size: 0.78rem; font-weight: 700; color: ${h.is_suspended ? '#f59e0b' : 'var(--accent-emerald)'};">
                ${h.is_suspended ? 'Suspended' : 'Live'}
              </span>
            </div>
          </td>
          <td>
            <div class="actions-cell">
              ${canExport ? `
                <a href="/api/hosts/${h.id}/export-conf?role=${encodeURIComponent(activeRole)}" class="btn-icon" title="Export .conf (Migration)" download>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>
                </a>
              ` : ''}
              <button class="btn-icon" title="View Generated Nginx Config" onclick="openNginxConfigModal(${h.id})">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
              </button>
              ${canEdit ? `
                <button class="btn-icon" title="Edit Host" onclick="openEditHostModal(${h.id})">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                </button>
              ` : `
                <button class="btn-icon disabled" title="Webmasters cannot edit existing hosts" disabled>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                </button>
              `}
              ${canDelete ? `
                <button class="btn-icon danger" title="Delete Host" onclick="deleteHost(${h.id}, '${escapeHtml(primaryDomain)}')">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
                </button>
              ` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    renderPagination(paginationEl, hostsCurrentPage, totalPages, filtered.length, startIndex, pageItems.length, (p) => {
      hostsCurrentPage = p;
      renderHostsTable();
    });
  }

  // Filter pills
  document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      currentFilter = pill.getAttribute('data-filter');
      hostsCurrentPage = 1;
      renderHostsTable();
    });
  });

  document.getElementById('host-search-input').addEventListener('input', () => {
    hostsCurrentPage = 1;
    renderHostsTable();
  });

  document.getElementById('btn-refresh-hosts').addEventListener('click', () => {
    loadHosts();
    showToast('Proxy hosts refreshed');
  });

  // -----------------------------------------------------
  // Toggle Suspension
  // -----------------------------------------------------
  window.toggleHostSuspension = async function(id) {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can suspend domains', 'error');
      loadHosts();
      return;
    }
    try {
      const res = await fetch(`/api/hosts/${id}/toggle-suspend`, { method: 'POST' });
      const data = await res.json();
      showToast(data.message, data.is_suspended ? 'warning' : 'success');
      loadHosts();
    } catch (err) {
      showToast('Failed to toggle host status', 'error');
    }
  };

  // -----------------------------------------------------
  // Delete Host
  // -----------------------------------------------------
  window.deleteHost = async function(id, domain) {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can delete hosts', 'error');
      return;
    }
    if (!confirm(`Are you sure you want to delete proxy host for ${domain}?`)) {
      return;
    }
    try {
      const res = await fetch(`/api/hosts/${id}`, { method: 'DELETE' });
      const data = await res.json();
      showToast(data.message, 'success');
      loadHosts();
    } catch (err) {
      showToast('Failed to delete proxy host', 'error');
    }
  };

  // -----------------------------------------------------
  // Add / Edit Host Modal
  // -----------------------------------------------------
  const hostModal = document.getElementById('host-modal');
  const hostForm = document.getElementById('host-form');
  const hostModalTitle = document.getElementById('host-modal-title');

  document.getElementById('btn-open-create-modal').addEventListener('click', () => {
    if (activeRole !== 'super_admin' && activeRole !== 'webmaster') {
      showToast('Permission denied: Your role cannot add domains', 'error');
      return;
    }
    hostModalTitle.textContent = 'Add New Proxy Host';
    document.getElementById('edit-host-id').value = '';
    hostForm.reset();
    document.getElementById('input-app-name').value = '';
    document.getElementById('input-forward-scheme').value = 'http';
    document.getElementById('input-forward-host').value = '127.0.0.1';
    document.getElementById('input-forward-port').value = '8080';
    document.getElementById('input-websocket').checked = true;
    document.getElementById('input-block-exploits').checked = true;
    document.getElementById('input-ssl-forced').checked = true;
    document.getElementById('input-suspended-reason').value = 'Administrative Policy Suspension';
    hostModal.classList.add('open');
  });

  document.getElementById('btn-close-host-modal').addEventListener('click', () => {
    hostModal.classList.remove('open');
  });
  document.getElementById('btn-cancel-host-modal').addEventListener('click', () => {
    hostModal.classList.remove('open');
  });

  window.openEditHostModal = function(id) {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can edit hosts', 'error');
      return;
    }
    const h = hostsData.find(item => item.id === id);
    if (!h) return;

    hostModalTitle.textContent = `Edit Proxy Host #${h.id}`;
    document.getElementById('edit-host-id').value = h.id;
    document.getElementById('input-domain-names').value = h.domain_names;
    document.getElementById('input-app-name').value = h.app_name || '';
    document.getElementById('input-forward-scheme').value = h.forward_scheme;
    document.getElementById('input-forward-host').value = h.forward_host;
    document.getElementById('input-forward-port').value = h.forward_port;
    document.getElementById('input-websocket').checked = h.websocket_support;
    document.getElementById('input-block-exploits').checked = h.block_exploits;
    document.getElementById('input-ssl-forced').checked = h.ssl_forced;
    document.getElementById('input-suspended-reason').value = h.suspended_reason || 'Administrative Policy Suspension';
    document.getElementById('input-custom-nginx').value = h.custom_nginx_config || '';

    hostModal.classList.add('open');
  };

  hostForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const editId = document.getElementById('edit-host-id').value;

    if (editId && activeRole !== 'super_admin') {
      showToast('Permission denied: Webmasters cannot edit existing hosts', 'error');
      return;
    }

    const payload = {
      domain_names: document.getElementById('input-domain-names').value.trim(),
      app_name: (document.getElementById('input-app-name').value || '').trim() || 'Web Application',
      forward_scheme: document.getElementById('input-forward-scheme').value,
      forward_host: document.getElementById('input-forward-host').value.trim(),
      forward_port: parseInt(document.getElementById('input-forward-port').value, 10),
      websocket_support: document.getElementById('input-websocket').checked,
      block_exploits: document.getElementById('input-block-exploits').checked,
      ssl_forced: document.getElementById('input-ssl-forced').checked,
      suspended_reason: document.getElementById('input-suspended-reason').value.trim(),
      custom_nginx_config: document.getElementById('input-custom-nginx').value.trim()
    };

    try {
      let res;
      if (editId) {
        res = await fetch(`/api/hosts/${editId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
      } else {
        res = await fetch('/api/hosts', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
      }

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Error saving host');
      }

      showToast(editId ? 'Proxy host updated successfully' : 'Proxy host created successfully', 'success');
      hostModal.classList.remove('open');
      loadHosts();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // -----------------------------------------------------
  // Nginx Config Viewer & Validation
  // -----------------------------------------------------
  const configModal = document.getElementById('config-modal');
  const configModalCode = document.getElementById('config-modal-code');
  const modalValidationResult = document.getElementById('modal-validation-result');

  window.openNginxConfigModal = async function(id) {
    try {
      const res = await fetch(`/api/hosts/${id}/nginx-config`);
      const data = await res.json();
      configModalCode.textContent = data.nginx_config;
      modalValidationResult.style.display = 'none';
      configModal.classList.add('open');
    } catch (err) {
      showToast('Failed to fetch Nginx config', 'error');
    }
  };

  document.getElementById('btn-close-config-modal').addEventListener('click', () => {
    configModal.classList.remove('open');
  });
  document.getElementById('btn-close-config-done').addEventListener('click', () => {
    configModal.classList.remove('open');
  });

  document.getElementById('btn-copy-config').addEventListener('click', () => {
    navigator.clipboard.writeText(configModalCode.textContent).then(() => {
      showToast('Nginx configuration copied to clipboard!');
    });
  });

  document.getElementById('btn-validate-modal-config').addEventListener('click', async () => {
    const configText = configModalCode.textContent;
    try {
      const res = await fetch('/api/validate-nginx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config_text: configText })
      });
      const data = await res.json();

      modalValidationResult.style.display = 'block';
      if (data.valid) {
        modalValidationResult.innerHTML = `
          <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid var(--accent-emerald); border-radius: 8px; padding: 0.75rem; color: var(--accent-emerald); font-size: 0.85rem; font-weight: 600;">
            [PASS] ${escapeHtml(data.message)}
          </div>
        `;
        showToast('Syntax Test Passed!', 'success');
      } else {
        modalValidationResult.innerHTML = `
          <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 0.75rem; color: #ef4444; font-size: 0.85rem;">
            <strong>[FAIL] Syntax Test Failed:</strong>
            <ul style="margin: 0.4rem 0 0 1.25rem;">
              ${data.errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
            </ul>
          </div>
        `;
        showToast('Syntax Test Failed!', 'error');
      }
    } catch (err) {
      showToast('Error validating syntax', 'error');
    }
  });

  // -----------------------------------------------------
  // Dedicated Nginx Syntax Tester Tab
  // -----------------------------------------------------
  const nginxTestEditor = document.getElementById('nginx-test-editor');
  const nginxValidationOutput = document.getElementById('nginx-validation-output');

  document.getElementById('btn-validate-now').addEventListener('click', async () => {
    const text = nginxTestEditor.value;
    try {
      const res = await fetch('/api/validate-nginx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config_text: text })
      });
      const data = await res.json();
      nginxValidationOutput.style.display = 'block';

      if (data.valid) {
        nginxValidationOutput.innerHTML = `
          <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid var(--accent-emerald); border-radius: 8px; padding: 0.85rem; color: var(--accent-emerald); font-size: 0.88rem; font-weight: 600;">
            [PASS] ${escapeHtml(data.message)}
          </div>
        `;
        showToast('Nginx syntax check passed!', 'success');
      } else {
        nginxValidationOutput.innerHTML = `
          <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 0.85rem; color: #ef4444; font-size: 0.88rem;">
            <strong>[FAIL] Syntax Error:</strong>
            <ul style="margin: 0.4rem 0 0 1.25rem;">
              ${data.errors.map(e => `<li>${escapeHtml(e)}</li>`).join('')}
            </ul>
          </div>
        `;
        showToast('Syntax errors found', 'error');
      }
    } catch (err) {
      showToast('Validation request failed', 'error');
    }
  });

  document.getElementById('btn-load-sample-config').addEventListener('click', () => {
    nginxTestEditor.value = `server {
    listen 80;
    server_name portal.novacloudedges.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}`;
    showToast('Loaded sample reverse proxy configuration');
  });

  // -----------------------------------------------------
  // UFW Firewall & WAF Rules (Super Admin, 10 Records Per Page)
  // -----------------------------------------------------
  let ufwCurrentPage = 1;
  const UFW_PER_PAGE = 10;

  async function loadUfwRules() {
    try {
      const res = await fetch('/api/ufw/rules');
      ufwRulesData = await res.json();
      renderUfwTable();
      loadUfwCliStatus();
    } catch (err) {
      showToast('Error loading UFW rules', 'error');
    }
  }

  function renderUfwTable() {
    const tbody = document.getElementById('ufw-rules-table-body');
    const paginationEl = document.getElementById('ufw-pagination');

    if (!ufwRulesData || ufwRulesData.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">
            No UFW firewall rules configured.
          </td>
        </tr>
      `;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(ufwRulesData.length / UFW_PER_PAGE);
    if (ufwCurrentPage > totalPages) ufwCurrentPage = totalPages;
    if (ufwCurrentPage < 1) ufwCurrentPage = 1;

    const startIndex = (ufwCurrentPage - 1) * UFW_PER_PAGE;
    const pageItems = ufwRulesData.slice(startIndex, startIndex + UFW_PER_PAGE);

    tbody.innerHTML = pageItems.map(r => {
      const badgeClass = r.rule_type.toLowerCase();
      return `
        <tr>
          <td style="font-family: var(--font-primary); font-size: 0.82rem;">#${r.id}</td>
          <td><span class="ufw-badge ${badgeClass}">${escapeHtml(r.rule_type)}</span></td>
          <td><strong>${escapeHtml(r.port)}</strong></td>
          <td style="font-family: var(--font-primary); font-size: 0.8rem; text-transform: uppercase;">${escapeHtml(r.protocol)}</td>
          <td style="font-family: var(--font-primary); font-size: 0.82rem; color: var(--secondary);">${escapeHtml(r.from_ip)}</td>
          <td>${escapeHtml(r.comment)}</td>
          <td>
            <label class="switch" title="Toggle rule active/inactive">
              <input type="checkbox" ${r.is_active ? 'checked' : ''} onchange="toggleUfwRule(${r.id})">
              <span class="slider"></span>
            </label>
          </td>
          <td style="text-align: right;">
            <div class="actions-cell" style="justify-content: flex-end;">
              <button class="btn-icon" title="Edit UFW Rule" onclick="openEditUfwModal(${r.id})">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
              </button>
              <button class="btn-icon danger" title="Delete Rule" onclick="deleteUfwRule(${r.id})">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    renderPagination(paginationEl, ufwCurrentPage, totalPages, ufwRulesData.length, startIndex, pageItems.length, (p) => {
      ufwCurrentPage = p;
      renderUfwTable();
    });
  }

  async function loadUfwCliStatus() {
    try {
      const res = await fetch('/api/ufw/status');
      const data = await res.json();
      document.getElementById('ufw-cli-output').textContent = data.raw_cli_output;
    } catch (err) {
      console.error(err);
    }
  }

  document.getElementById('btn-copy-ufw-cli').addEventListener('click', () => {
    navigator.clipboard.writeText(document.getElementById('ufw-cli-output').textContent).then(() => {
      showToast('UFW numbered status copied to clipboard!');
    });
  });

  const ufwModal = document.getElementById('ufw-modal');
  const ufwForm = document.getElementById('ufw-form');

  window.openEditUfwModal = function(id) {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can manage UFW', 'error');
      return;
    }
    const rule = ufwRulesData.find(r => r.id === id);
    if (!rule) {
      showToast('Rule not found', 'error');
      return;
    }
    document.getElementById('ufw-edit-id').value = rule.id;
    document.getElementById('ufw-modal-title').textContent = `Edit UFW Rule #${rule.id}`;
    const submitBtn = document.getElementById('ufw-submit-btn');
    if (submitBtn) submitBtn.textContent = 'Update UFW Rule';
    document.getElementById('ufw-rule-type').value = rule.rule_type;
    document.getElementById('ufw-port').value = rule.port;
    document.getElementById('ufw-protocol').value = rule.protocol;
    document.getElementById('ufw-source-ip').value = rule.from_ip;
    document.getElementById('ufw-comment').value = rule.comment || '';
    ufwModal.classList.add('open');
  };

  document.getElementById('btn-open-ufw-modal').addEventListener('click', () => {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can manage UFW', 'error');
      return;
    }
    ufwForm.reset();
    document.getElementById('ufw-edit-id').value = '';
    document.getElementById('ufw-modal-title').textContent = 'Add UFW Firewall Rule';
    const submitBtn = document.getElementById('ufw-submit-btn');
    if (submitBtn) submitBtn.textContent = 'Apply UFW Rule';
    document.getElementById('ufw-rule-type').value = 'ALLOW';
    document.getElementById('ufw-port').value = '80';
    document.getElementById('ufw-protocol').value = 'tcp';
    document.getElementById('ufw-source-ip').value = 'Anywhere';
    ufwModal.classList.add('open');
  });

  document.getElementById('btn-close-ufw-modal').addEventListener('click', () => {
    ufwModal.classList.remove('open');
  });
  document.getElementById('btn-cancel-ufw-modal').addEventListener('click', () => {
    ufwModal.classList.remove('open');
  });

  ufwForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const editId = document.getElementById('ufw-edit-id').value;
    const payload = {
      rule_type: document.getElementById('ufw-rule-type').value,
      port: document.getElementById('ufw-port').value.trim(),
      protocol: document.getElementById('ufw-protocol').value,
      from_ip: document.getElementById('ufw-source-ip').value.trim(),
      comment: document.getElementById('ufw-comment').value.trim()
    };

    try {
      const url = editId ? `/api/ufw/rules/${editId}` : '/api/ufw/rules';
      const method = editId ? 'PUT' : 'POST';
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (!res.ok) {
        const err = await res.json();
        showToast(err.detail || 'Error saving UFW rule', 'error');
        return;
      }
      const data = await res.json();
      showToast(data.message, 'success');
      ufwModal.classList.remove('open');
      loadUfwRules();
      loadSystemStatus();
    } catch (err) {
      showToast('Error saving UFW rule', 'error');
    }
  });

  window.toggleUfwRule = async function(id) {
    try {
      const res = await fetch(`/api/ufw/rules/${id}/toggle`, { method: 'POST' });
      const data = await res.json();
      showToast(data.message, 'success');
      loadUfwRules();
      loadSystemStatus();
    } catch (err) {
      showToast('Error toggling rule', 'error');
    }
  };

  window.deleteUfwRule = async function(id) {
    if (!confirm(`Delete UFW Rule #${id}?`)) return;
    try {
      const res = await fetch(`/api/ufw/rules/${id}`, { method: 'DELETE' });
      const data = await res.json();
      showToast(data.message, 'success');
      loadUfwRules();
      loadSystemStatus();
    } catch (err) {
      showToast('Error deleting rule', 'error');
    }
  };

  document.getElementById('btn-refresh-ufw').addEventListener('click', () => {
    loadUfwRules();
    showToast('UFW rules refreshed');
  });

  // -----------------------------------------------------
  // Team Users Management (Super Admin) — Add, Edit, Delete, Suspend
  // -----------------------------------------------------
  let usersCurrentPage = 1;
  const USERS_PER_PAGE = 10;

  async function loadUsers() {
    try {
      const res = await fetch('/api/users');
      usersData = await res.json();
      renderUsersTable();
    } catch (err) {
      showToast('Error loading user accounts', 'error');
    }
  }

  function renderUsersTable() {
    const tbody = document.getElementById('users-table-body');
    const paginationEl = document.getElementById('users-pagination');

    if (!usersData || usersData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">No users found.</td></tr>`;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(usersData.length / USERS_PER_PAGE);
    if (usersCurrentPage > totalPages) usersCurrentPage = totalPages;
    if (usersCurrentPage < 1) usersCurrentPage = 1;

    const startIndex = (usersCurrentPage - 1) * USERS_PER_PAGE;
    const pageItems = usersData.slice(startIndex, startIndex + USERS_PER_PAGE);

    tbody.innerHTML = pageItems.map(u => {
      let roleBadgeStyle = 'background: rgba(2, 132, 199, 0.12); color: var(--secondary);';
      if (u.role === 'super_admin') roleBadgeStyle = 'background: rgba(16, 185, 129, 0.12); color: var(--accent-emerald);';
      if (u.role === 'security') roleBadgeStyle = 'background: rgba(245, 158, 11, 0.12); color: #f59e0b;';
      if (u.role === 'billing') roleBadgeStyle = 'background: rgba(168, 85, 247, 0.12); color: #a855f7;';

      const isPrimaryAdmin = u.id === 1;

      return `
        <tr>
          <td style="font-family: var(--font-primary); font-size: 0.82rem;">#${u.id}</td>
          <td>
            <div style="display: flex; flex-direction: column;">
              <strong style="color: var(--text-main);">${escapeHtml(u.full_name)}</strong>
              <span style="font-size: 0.76rem; color: var(--text-muted); font-family: var(--font-primary);">@${escapeHtml(u.username)}</span>
            </div>
          </td>
          <td><span style="font-size: 0.85rem; font-family: var(--font-primary);">${escapeHtml(u.email)}</span></td>
          <td>
            <span class="badge-tag" style="${roleBadgeStyle} font-size: 0.74rem; padding: 0.2rem 0.55rem; border-radius: 6px; font-weight: 700; text-transform: uppercase;">
              ${escapeHtml(u.role.replace('_', ' '))}
            </span>
          </td>
          <td>
            <span class="user-status-badge ${u.is_active ? 'active' : 'suspended'}">
              <span class="pulse-dot ${u.is_active ? '' : 'warning'}" style="width: 5px; height: 5px;"></span>
              ${u.is_active ? 'Active' : 'Suspended'}
            </span>
          </td>
          <td style="text-align: right;">
            <div class="btn-action-group">
              <button class="btn-secondary btn-sm" title="Edit User Account" onclick="openEditUserModal(${u.id})">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                Edit
              </button>
              ${!isPrimaryAdmin ? `
                <button class="${u.is_active ? 'btn-warning' : 'btn-emerald'} btn-sm" title="${u.is_active ? 'Suspend account access' : 'Reactivate account'}" onclick="suspendUserAccount(${u.id}, ${u.is_active ? 'true' : 'false'})">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" x2="19.07" y1="4.93" y2="19.07"/></svg>
                  ${u.is_active ? 'Suspend' : 'Reactivate'}
                </button>
                <button class="btn-icon danger" title="Delete User" onclick="deleteUserAccount(${u.id}, '${escapeHtml(u.username)}')">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg>
                </button>
              ` : `
                <span class="role-lock-badge" style="background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border-color: rgba(16, 185, 129, 0.3); padding: 0.25rem 0.6rem;">Protected</span>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    renderPagination(paginationEl, usersCurrentPage, totalPages, usersData.length, startIndex, pageItems.length, (p) => {
      usersCurrentPage = p;
      renderUsersTable();
    });
  }

  const userModal = document.getElementById('user-modal');
  const userForm = document.getElementById('user-form');
  const userModalTitle = document.getElementById('user-modal-title');
  const editUserIdInput = document.getElementById('edit-user-id');
  const userUsernameInput = document.getElementById('user-username');
  const userStatusGroup = document.getElementById('user-status-group');
  const userPassHint = document.getElementById('user-pass-hint');
  const btnSaveUser = document.getElementById('btn-save-user');

  document.getElementById('btn-open-user-modal').addEventListener('click', () => {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can add users', 'error');
      return;
    }
    userForm.reset();
    editUserIdInput.value = '';
    userModalTitle.textContent = 'Add Team Member';
    btnSaveUser.textContent = 'Create User Account';
    userUsernameInput.disabled = false;
    userUsernameInput.style.opacity = '1';
    userStatusGroup.style.display = 'none';
    userPassHint.textContent = '(Set initial password)';
    document.getElementById('user-role').value = 'webmaster';
    userModal.classList.add('open');
  });

  window.openEditUserModal = async function(id) {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can edit users', 'error');
      return;
    }
    try {
      const res = await fetch(`/api/users/${id}`);
      if (!res.ok) throw new Error('Could not fetch user details');
      const u = await res.json();

      editUserIdInput.value = u.id;
      document.getElementById('user-fullname').value = u.full_name;
      userUsernameInput.value = u.username;
      userUsernameInput.disabled = true;
      userUsernameInput.style.opacity = '0.7';
      document.getElementById('user-email').value = u.email;
      document.getElementById('user-role').value = u.role;
      document.getElementById('user-password').value = '';
      document.getElementById('user-is-active').checked = !!u.is_active;

      userStatusGroup.style.display = u.id === 1 ? 'none' : 'block';
      userPassHint.textContent = '(Leave blank to keep existing password)';
      userModalTitle.textContent = `Edit User: @${u.username}`;
      btnSaveUser.textContent = 'Save Changes';

      userModal.classList.add('open');
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  document.getElementById('btn-close-user-modal').addEventListener('click', () => {
    userModal.classList.remove('open');
  });
  document.getElementById('btn-cancel-user-modal').addEventListener('click', () => {
    userModal.classList.remove('open');
  });

  userForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const editId = editUserIdInput.value;

    if (editId) {
      // Edit User
      const payload = {
        full_name: document.getElementById('user-fullname').value.trim(),
        email: document.getElementById('user-email').value.trim(),
        role: document.getElementById('user-role').value,
        password: document.getElementById('user-password').value || null,
        is_active: document.getElementById('user-is-active').checked
      };

      try {
        const res = await fetch(`/api/users/${editId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Error updating user');

        showToast(data.message, 'success');
        userModal.classList.remove('open');
        loadUsers();
      } catch (err) {
        showToast(err.message, 'error');
      }
    } else {
      // Create User
      const payload = {
        full_name: document.getElementById('user-fullname').value.trim(),
        username: document.getElementById('user-username').value.trim(),
        email: document.getElementById('user-email').value.trim(),
        role: document.getElementById('user-role').value,
        password: document.getElementById('user-password').value
      };

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Error adding user');

        showToast(data.message, 'success');
        userModal.classList.remove('open');
        loadUsers();
      } catch (err) {
        showToast(err.message, 'error');
      }
    }
  });

  window.suspendUserAccount = async function(id, suspend) {
    const actionLabel = suspend ? 'suspend' : 'reactivate';
    if (!confirm(`Are you sure you want to ${actionLabel} this user account?`)) return;
    try {
      const res = await fetch(`/api/users/${id}/suspend?suspend=${suspend}`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || `Error updating user`);
      showToast(data.message, suspend ? 'warning' : 'success');
      loadUsers();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  window.deleteUserAccount = async function(id, username) {
    if (!confirm(`Are you sure you want to permanently delete user account @${username}?`)) return;
    try {
      const res = await fetch(`/api/users/${id}`, { method: 'DELETE' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Error deleting user');
      showToast(data.message, 'success');
      loadUsers();
    } catch (err) {
      showToast(err.message, 'error');
    }
  };

  document.getElementById('btn-refresh-users').addEventListener('click', () => {
    loadUsers();
    showToast('User accounts refreshed');
  });

  // -----------------------------------------------------
  // Nginx Backup & Server Migration Engine Event Handlers (Super Admin Only)
  // -----------------------------------------------------
  const btnExportAllZip = document.getElementById('btn-export-all-zip');
  if (btnExportAllZip) {
    btnExportAllZip.addEventListener('click', () => {
      if (activeRole !== 'super_admin') {
        showToast('Restricted Action: Exporting Nginx backup archives is only permitted for Super Admin.', 'error');
        return;
      }
      showToast('Preparing complete Nginx backup archive (.zip)...');
      window.location.href = `/api/nginx/export/all?role=${encodeURIComponent(activeRole)}`;
    });
  }

  const migrateModal = document.getElementById('migrate-modal');
  const btnOpenMigrate = document.getElementById('btn-open-migrate-modal');
  const btnCloseMigrate = document.getElementById('btn-close-migrate-modal');
  const btnCancelMigrate = document.getElementById('btn-cancel-migrate-modal');
  const migrateForm = document.getElementById('migrate-form');
  const migrateFileInput = document.getElementById('migrate-file-input');
  const migrateConfText = document.getElementById('migrate-conf-text');
  const migrateResultBox = document.getElementById('migrate-result-box');

  if (btnOpenMigrate) {
    btnOpenMigrate.addEventListener('click', () => {
      if (activeRole !== 'super_admin') {
        showToast('Restricted Action: Importing and migrating server configs is only permitted for Super Admin.', 'error');
        return;
      }
      migrateForm.reset();
      migrateResultBox.style.display = 'none';
      migrateModal.classList.add('open');
    });
  }

  if (btnCloseMigrate) btnCloseMigrate.addEventListener('click', () => migrateModal.classList.remove('open'));
  if (btnCancelMigrate) btnCancelMigrate.addEventListener('click', () => migrateModal.classList.remove('open'));

  if (migrateFileInput) {
    migrateFileInput.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (event) => {
        migrateConfText.value = event.target.result;
        showToast(`Loaded configuration file: ${file.name}`);
      };
      reader.readAsText(file);
    });
  }

  if (migrateForm) {
    migrateForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (activeRole !== 'super_admin') {
        showToast('Restricted Action: Importing server configurations is only permitted for Super Admin.', 'error');
        return;
      }
      const confContent = migrateConfText.value.trim();
      if (!confContent) {
        showToast('Please paste or upload Nginx configuration content.', 'error');
        return;
      }

      const overwrite = document.getElementById('migrate-overwrite').checked;
      const submitBtn = document.getElementById('btn-submit-migrate');
      submitBtn.disabled = true;
      submitBtn.innerHTML = `<span>Importing & Validating...</span>`;

      try {
        const res = await fetch('/api/nginx/import/all', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-User-Role': activeRole
          },
          body: JSON.stringify({ conf_content: confContent, overwrite: overwrite })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Migration import failed');

        migrateResultBox.style.display = 'block';
        migrateResultBox.innerHTML = `
          <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 8px; padding: 0.75rem 0.95rem; font-size: 0.82rem; color: var(--accent-emerald);">
            <strong style="display: block; margin-bottom: 0.25rem;">Migration Successful:</strong>
            ${escapeHtml(data.message)} (${data.imported_count} virtual hosts restored)
          </div>
        `;

        showToast(data.message, 'success');
        loadHosts();
        setTimeout(() => {
          migrateModal.classList.remove('open');
          submitBtn.disabled = false;
          submitBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Import & Migrate Configuration`;
        }, 1200);
      } catch (err) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg> Import & Migrate Configuration`;
        showToast(err.message, 'error');
      }
    });
  }

  // -----------------------------------------------------
  // Security Role: WHOIS & Abuse Reporting
  // -----------------------------------------------------
  document.getElementById('btn-run-whois').addEventListener('click', async () => {
    const domain = (document.getElementById('whois-domain-input').value || '').trim();
    if (!domain) {
      showToast('Please enter a domain for WHOIS query', 'warning');
      return;
    }
    const resultPre = document.getElementById('whois-result-pre');
    resultPre.textContent = `Querying WHOIS records for ${domain}...`;
    try {
      const res = await fetch(`/api/whois/${encodeURIComponent(domain)}`);
      const data = await res.json();
      resultPre.textContent = JSON.stringify(data, null, 2);
      showToast(`WHOIS query complete for ${domain}`);
    } catch (err) {
      resultPre.textContent = 'Error querying WHOIS service';
    }
  });

  const abuseForm = document.getElementById('abuse-report-form');
  abuseForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = {
      domain: document.getElementById('abuse-domain').value.trim(),
      source_ip: document.getElementById('abuse-ip').value.trim(),
      abuse_category: document.getElementById('abuse-category').value,
      notes: document.getElementById('abuse-notes').value.trim(),
      block_in_ufw: true
    };

    try {
      const res = await fetch('/api/abuse-reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      showToast(data.message, 'success');
      abuseForm.reset();
      loadAbuseReports();
      loadSystemStatus();
    } catch (err) {
      showToast('Failed to submit abuse report', 'error');
    }
  });

  let abuseData = [];
  let abuseCurrentPage = 1;
  const ABUSE_PER_PAGE = 10;

  async function loadAbuseReports() {
    try {
      const res = await fetch('/api/abuse-reports');
      abuseData = await res.json();
      renderAbuseTable();
    } catch (err) {
      console.error(err);
    }
  }

  function renderAbuseTable() {
    const tbody = document.getElementById('abuse-table-body');
    const paginationEl = document.getElementById('abuse-pagination');
    if (!abuseData || abuseData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">No abuse reports registered.</td></tr>`;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(abuseData.length / ABUSE_PER_PAGE);
    if (abuseCurrentPage > totalPages) abuseCurrentPage = totalPages;
    if (abuseCurrentPage < 1) abuseCurrentPage = 1;

    const startIndex = (abuseCurrentPage - 1) * ABUSE_PER_PAGE;
    const pageItems = abuseData.slice(startIndex, startIndex + ABUSE_PER_PAGE);

    tbody.innerHTML = pageItems.map(r => `
      <tr>
        <td style="font-family: var(--font-primary); font-size: 0.8rem; color: var(--text-muted);">${escapeHtml(r.created_at)}</td>
        <td><strong style="color: var(--text-main); font-family: var(--font-primary);">${escapeHtml(r.domain)}</strong></td>
        <td style="font-family: var(--font-primary); color: #ef4444; font-weight: 700;">${escapeHtml(r.source_ip)}</td>
        <td>${escapeHtml(r.abuse_category)}</td>
        <td><span class="ufw-badge deny">${escapeHtml(r.action_taken)}</span></td>
        <td><span class="ssl-badge valid">${escapeHtml(r.status)}</span></td>
      </tr>
    `).join('');

    renderPagination(paginationEl, abuseCurrentPage, totalPages, abuseData.length, startIndex, pageItems.length, (p) => {
      abuseCurrentPage = p;
      renderAbuseTable();
    });
  }

  document.getElementById('btn-refresh-abuse').addEventListener('click', () => {
    abuseCurrentPage = 1;
    loadAbuseReports();
    showToast('Abuse incident list refreshed');
  });

  // -----------------------------------------------------
  // Billing Role: Expiry Timelines (10 Records Per Page)
  // -----------------------------------------------------
  let billingCurrentPage = 1;
  const BILLING_PER_PAGE = 10;

  async function loadBillingData() {
    try {
      const res = await fetch('/api/certificates');
      certsData = await res.json();
      renderBillingTable();
    } catch (err) {
      showToast('Error loading certificate & billing data', 'error');
    }
  }

  function renderBillingTable() {
    const tbody = document.getElementById('billing-table-body');
    const paginationEl = document.getElementById('billing-pagination');
    if (!certsData || certsData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">No domains or SSL certificates found.</td></tr>`;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(certsData.length / BILLING_PER_PAGE);
    if (billingCurrentPage > totalPages) billingCurrentPage = totalPages;
    if (billingCurrentPage < 1) billingCurrentPage = 1;

    const startIndex = (billingCurrentPage - 1) * BILLING_PER_PAGE;
    const pageItems = certsData.slice(startIndex, startIndex + BILLING_PER_PAGE);
    const today = new Date();

    tbody.innerHTML = pageItems.map(c => {
      const expDate = new Date(c.expires_at);
      const diffDays = Math.ceil((expDate - today) / (1000 * 60 * 60 * 24));

      let domainExpiryHtml = '<span style="color: var(--text-muted); font-size: 0.8rem;">Auto-synced</span>';
      if (c.domain_expires_at) {
        const domExpDate = new Date(c.domain_expires_at);
        const domDiffDays = Math.ceil((domExpDate - today) / (1000 * 60 * 60 * 24));
        const domExpBadgeClass = domDiffDays <= 30 ? 'expiring' : 'valid';
        domainExpiryHtml = `
          <div style="display: flex; flex-direction: column;">
            <strong style="font-family: var(--font-primary); font-size: 0.82rem;">${escapeHtml(c.domain_expires_at)}</strong>
            <span style="font-size: 0.73rem; color: var(--text-muted);">${domDiffDays > 0 ? `${domDiffDays} days left` : 'Expired'}</span>
          </div>
        `;
      }

      let urgencyBadge = '<span class="ssl-badge valid">Healthy (>30d)</span>';
      if (diffDays <= 15) {
        urgencyBadge = '<span class="ssl-badge expiring">Urgent (<15d)</span>';
      } else if (diffDays <= 30) {
        urgencyBadge = '<span class="ssl-badge expiring">Expiring Soon</span>';
      }

      return `
        <tr>
          <td><strong style="font-family: var(--font-primary);">${escapeHtml(c.domain)}</strong></td>
          <td>${escapeHtml(c.provider)}</td>
          <td>${domainExpiryHtml}</td>
          <td><strong>${escapeHtml(c.expires_at)}</strong> <span style="font-size: 0.76rem; color: var(--text-muted);">(${diffDays} days left)</span></td>
          <td>${c.auto_renew ? '<span style="color: var(--accent-emerald); font-weight: 700;">Auto-Renew Enabled</span>' : '<span style="color: var(--text-muted);">Manual Renewal</span>'}</td>
          <td>${urgencyBadge}</td>
          <td style="text-align: right;">
            <button class="btn-secondary btn-sm" onclick="renewCert('${escapeHtml(c.domain)}')">
              Renew Subscription
            </button>
          </td>
        </tr>
      `;
    }).join('');

    renderPagination(paginationEl, billingCurrentPage, totalPages, certsData.length, startIndex, pageItems.length, (p) => {
      billingCurrentPage = p;
      renderBillingTable();
    });
  }

  window.renewCert = async function(domain) {
    try {
      const res = await fetch(`/api/certificates/renew?domain=${encodeURIComponent(domain)}`, { method: 'POST' });
      const data = await res.json();
      showToast(data.message, 'success');
      loadBillingData();
      loadHosts();
    } catch (err) {
      showToast('Failed to renew certificate', 'error');
    }
  };

  document.getElementById('btn-refresh-billing').addEventListener('click', () => {
    billingCurrentPage = 1;
    loadBillingData();
    showToast('Billing expiration data refreshed');
  });

  // -----------------------------------------------------
  // Suspension Statement Settings
  // -----------------------------------------------------
  async function loadSuspensionSettings() {
    try {
      const res = await fetch('/api/suspension-settings');
      const data = await res.json();
      document.getElementById('susp-title-input').value = data.title;
      document.getElementById('susp-msg-input').value = data.message;
      document.getElementById('susp-email-input').value = data.contact_email;
      document.getElementById('susp-phone-input').value = data.contact_phone;
    } catch (err) {
      console.error(err);
    }
  }

  const suspensionForm = document.getElementById('suspension-settings-form');
  suspensionForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can modify suspension statement', 'error');
      return;
    }
    const payload = {
      title: document.getElementById('susp-title-input').value.trim(),
      message: document.getElementById('susp-msg-input').value.trim(),
      contact_email: document.getElementById('susp-email-input').value.trim(),
      contact_phone: document.getElementById('susp-phone-input').value.trim()
    };

    try {
      const res = await fetch('/api/suspension-settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      showToast(data.message, 'success');
    } catch (err) {
      showToast('Failed to update suspension statement', 'error');
    }
  });

  // -----------------------------------------------------
  // Managed Action Email Notifications (SMTP)
  // -----------------------------------------------------
  async function loadSmtpSettings() {
    try {
      const res = await fetch('/api/smtp-settings');
      if (!res.ok) return;
      const data = await res.json();
      const hostInput = document.getElementById('smtp-host-input');
      const portInput = document.getElementById('smtp-port-input');
      const userInput = document.getElementById('smtp-user-input');
      const passInput = document.getElementById('smtp-pass-input');
      const toInput = document.getElementById('smtp-to-input');
      const tlsInput = document.getElementById('smtp-tls-input');

      if (hostInput) hostInput.value = data.smtp_host || '';
      if (portInput) portInput.value = data.smtp_port || 587;
      if (userInput) userInput.value = data.smtp_user || '';
      if (passInput && data.smtp_pass) {
        passInput.placeholder = '•••••••••••• (Configured)';
      }
      if (toInput) toInput.value = data.smtp_to_emails || '';
      if (tlsInput) tlsInput.value = data.smtp_encryption || 'starttls';

      const trUfw = document.getElementById('trigger-ufw');
      const trBlock = document.getElementById('trigger-blocking');
      const trSsl = document.getElementById('trigger-ssl');
      const trDom = document.getElementById('trigger-domain');
      const trSusp = document.getElementById('trigger-suspension');

      if (trUfw) trUfw.checked = !!data.smtp_trigger_ufw;
      if (trBlock) trBlock.checked = !!data.smtp_trigger_blocking;
      if (trSsl) trSsl.checked = !!data.smtp_trigger_ssl_expiry;
      if (trDom) trDom.checked = !!data.smtp_trigger_domain_expiry;
      if (trSusp) trSusp.checked = !!data.smtp_trigger_suspension;
    } catch (err) {
      console.error('Failed to load SMTP settings:', err);
    }
  }

  const smtpForm = document.getElementById('smtp-settings-form');
  if (smtpForm) {
    smtpForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (activeRole !== 'super_admin') {
        showToast('Permission denied: Only Super Admin can modify SMTP settings', 'error');
        return;
      }
      const payload = {
        smtp_host: document.getElementById('smtp-host-input').value.trim(),
        smtp_port: parseInt(document.getElementById('smtp-port-input').value, 10) || 587,
        smtp_user: document.getElementById('smtp-user-input').value.trim(),
        smtp_pass: document.getElementById('smtp-pass-input').value,
        smtp_to_emails: document.getElementById('smtp-to-input').value.trim(),
        smtp_encryption: document.getElementById('smtp-tls-input').value,
        smtp_trigger_ufw: document.getElementById('trigger-ufw').checked,
        smtp_trigger_blocking: document.getElementById('trigger-blocking').checked,
        smtp_trigger_ssl_expiry: document.getElementById('trigger-ssl').checked,
        smtp_trigger_domain_expiry: document.getElementById('trigger-domain').checked,
        smtp_trigger_suspension: document.getElementById('trigger-suspension').checked
      };

      try {
        const res = await fetch('/api/smtp-settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message || 'SMTP settings updated', 'success');
        } else {
          showToast(data.detail || 'Failed to update SMTP settings', 'error');
        }
      } catch (err) {
        showToast('Failed to save SMTP settings', 'error');
      }
    });
  }

  const btnTestSmtp = document.getElementById('btn-test-smtp');
  if (btnTestSmtp) {
    btnTestSmtp.addEventListener('click', async () => {
      const recipient = document.getElementById('smtp-to-input').value.trim();
      const originalHtml = btnTestSmtp.innerHTML;
      btnTestSmtp.disabled = true;
      btnTestSmtp.textContent = 'Sending Test Alert...';
      try {
        const res = await fetch('/api/smtp/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ test_email: recipient })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message, 'success');
        } else {
          showToast(data.detail || 'SMTP test error', 'error');
        }
      } catch (err) {
        showToast('SMTP test error: ' + err.message, 'error');
      } finally {
        btnTestSmtp.disabled = false;
        btnTestSmtp.innerHTML = originalHtml;
      }
    });
  }

  // -----------------------------------------------------
  // Audit Logs Tab (10 Records Per Page)
  // -----------------------------------------------------
  let logsData = [];
  let logsCurrentPage = 1;
  const LOGS_PER_PAGE = 10;

  async function loadAuditLogs() {
    try {
      const res = await fetch('/api/logs');
      logsData = await res.json();
      renderAuditLogsTable();
      loadLogAnalytics();
    } catch (err) {
      showToast('Error loading logs', 'error');
    }
  }

  async function loadLogAnalytics() {
    try {
      const res = await fetch('/api/logs/analytics');
      if (!res.ok) return;
      const data = await res.json();
      renderLogAnalytics(data);
    } catch (err) {
      console.warn('Error loading log analytics:', err);
    }
  }

  function renderLogAnalytics(data) {
    const totalEl = document.getElementById('ip-total-events');
    const uniqueEl = document.getElementById('ip-unique-count');
    const container = document.getElementById('access-ip-bars-container');
    if (!container) return;

    const totalEvents = data.total_events ?? data.total_logged_events ?? 0;
    const uniqueIps = data.unique_ips ?? data.unique_ips_count ?? 0;

    if (totalEl) totalEl.textContent = `${totalEvents} events`;
    if (uniqueEl) uniqueEl.textContent = `${uniqueIps} unique`;

    const topIps = (data.top_ips || []).slice(0, 6);
    const abnormalBadge = document.getElementById('abnormal-traffic-badge');
    const abnormalText = document.getElementById('abnormal-traffic-text');
    if (abnormalBadge && abnormalText) {
      if (data.abnormal_detected) {
        abnormalBadge.className = 'ssl-badge expiring';
        abnormalText.textContent = `${data.abnormal_traffic_count} Anomaly Alerts`;
      } else {
        abnormalBadge.className = 'ssl-badge valid';
        abnormalText.textContent = 'Normal Baseline';
      }
    }

    if (topIps.length === 0) {
      container.innerHTML = `<div style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 1.5rem; font-size: 0.85rem;">No client access activity logged yet.</div>`;
      return;
    }

    container.innerHTML = topIps.map(item => {
      const isLocal = item.ip === '127.0.0.1' || item.ip === '::1' || item.ip === 'localhost';
      const badgeClass = isLocal ? 'valid' : 'expiring';
      const badgeText = isLocal ? 'Localhost' : 'Remote Client';
      const pct = (typeof item.pct === 'number') ? item.pct : (typeof item.percentage === 'number' ? item.percentage : 0);

      return `
        <div class="ip-bar-row">
          <div class="ip-bar-header">
            <div class="ip-bar-meta">
              <span class="ip-address">${escapeHtml(item.ip)}</span>
              <span class="ssl-badge ${badgeClass}" style="font-size: 0.68rem; padding: 0.15rem 0.45rem;">${badgeText}</span>
            </div>
            <div class="ip-bar-stats">
              <span class="ip-count">${item.count} reqs</span>
              <span class="ip-pct">${pct.toFixed(1)}%</span>
            </div>
          </div>
          <div class="ip-bar-track">
            <div class="ip-bar-fill" style="width: ${Math.min(100, Math.max(3, pct))}%;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderAuditLogsTable() {
    const tbody = document.getElementById('logs-table-body');
    const paginationEl = document.getElementById('logs-pagination');

    if (!logsData || logsData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">No activity logs recorded.</td></tr>`;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(logsData.length / LOGS_PER_PAGE);
    if (logsCurrentPage > totalPages) logsCurrentPage = totalPages;
    if (logsCurrentPage < 1) logsCurrentPage = 1;

    const startIndex = (logsCurrentPage - 1) * LOGS_PER_PAGE;
    const pageItems = logsData.slice(startIndex, startIndex + LOGS_PER_PAGE);

    tbody.innerHTML = pageItems.map(l => {
      const isAbnormal = !!l.is_abnormal;
      const threatClass = l.threat_level === 'critical' ? 'expired' : (l.threat_level === 'warning' ? 'expiring' : 'valid');
      const threatText = l.threat_tag || (isAbnormal ? 'Abnormal Flag' : 'Normal');

      return `
        <tr style="${isAbnormal ? 'background: rgba(239, 68, 68, 0.04);' : ''}">
          <td style="white-space: nowrap; font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-primary);">${escapeHtml(l.timestamp)}</td>
          <td><strong style="color: var(--secondary);">${escapeHtml(l.action)}</strong></td>
          <td>${escapeHtml(l.details)}</td>
          <td><span class="ssl-badge valid">${escapeHtml(l.status)}</span></td>
          <td>
            <span class="ssl-badge ${threatClass}" style="font-size: 0.72rem; display: inline-flex; align-items: center; gap: 0.35rem;">
              <span class="pulse-dot ${isAbnormal ? 'warning' : ''}" style="width: 6px; height: 6px;"></span>
              ${escapeHtml(threatText)}
            </span>
          </td>
          <td style="font-family: var(--font-primary); font-size: 0.8rem;">${escapeHtml(l.client_ip)}</td>
        </tr>
      `;
    }).join('');

    renderPagination(paginationEl, logsCurrentPage, totalPages, logsData.length, startIndex, pageItems.length, (p) => {
      logsCurrentPage = p;
      renderAuditLogsTable();
    });
  }

  document.getElementById('btn-refresh-logs').addEventListener('click', () => {
    logsCurrentPage = 1;
    loadAuditLogs();
    showToast('Audit logs refreshed');
  });

  // Initial loads & telemetry intervals
  loadHosts();
  loadSystemMetrics();

  // Live telemetry polling (3s interval)
  setInterval(loadSystemMetrics, 3000);

  // Status & database health check (10s interval)
  setInterval(loadSystemStatus, 10000);
});

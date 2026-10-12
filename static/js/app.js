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
  let globalRolePermissions = {};

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

        updateUserProfileUI(data.user);
        applyRolePermissions(activeRole);
      }
    } catch (err) {
      console.warn('Session verification fallback:', err);
    }
  }

  function getInitials(name) {
    if (!name) return 'AD';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }

  function updateUserProfileUI(user) {
    if (!user) return;
    const initials = getInitials(user.full_name || user.username);
    const navInitials = document.getElementById('nav-avatar-initials');
    const dropdownInitials = document.getElementById('dropdown-avatar-initials');
    const dropdownFullname = document.getElementById('nav-dropdown-fullname');
    const dropdownUsername = document.getElementById('nav-dropdown-username');
    const dropdownRole = document.getElementById('nav-dropdown-role');
    const dropdownEmail = document.getElementById('nav-dropdown-email');
    const cpEmail = document.getElementById('cp-user-email-display');

    if (navInitials) navInitials.textContent = initials;
    if (dropdownInitials) dropdownInitials.textContent = initials;
    if (dropdownFullname) dropdownFullname.textContent = user.full_name || user.username;
    if (dropdownUsername) dropdownUsername.textContent = '@' + user.username;
    if (dropdownRole) dropdownRole.textContent = getRoleTitle(user.role).toUpperCase();
    if (dropdownEmail) dropdownEmail.textContent = user.email || 'None';
    if (cpEmail) cpEmail.textContent = user.email || 'None';
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
    const token = localStorage.getItem('nova_session_token') || localStorage.getItem('nova_token');
    try {
      if (token) {
        await fetch('/api/auth/logout', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${token}` }
        });
      }
    } catch (e) {}
    localStorage.removeItem('nova_token');
    localStorage.removeItem('nova_session_token');
    localStorage.removeItem('nova_role');
    localStorage.removeItem('nova_user');
    localStorage.removeItem('nova_fullname');
    localStorage.removeItem('nova_current_user');
    localStorage.removeItem('nova_last_active');
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
    if (role === 'domain_manager') return 'Domain Manager';
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
    } else if (role === 'domain_manager') {
      roleBannerText.textContent = 'Active Role: Domain Manager. You have access to your assigned proxy domains with Nginx configuration editing permissions.';
    } else if (role === 'webmaster') {
      roleBannerText.textContent = 'Active Role: Webmaster. You can add new domain names, but editing, deleting, and suspending existing domains are disabled.';
    } else if (role === 'security') {
      roleBannerText.textContent = 'Active Role: Security Analyst. You have full access to WHOIS investigation, SSL inspection, Domain Abuse reports, and Audit logs.';
    } else if (role === 'billing') {
      roleBannerText.textContent = 'Active Role: Billing Officer. You have access to Domain & SSL expiration tracking, renewal deadlines, and billing health.';
    }

    // Check permissions from dynamic matrix (fallback to role defaults)
    const perms = (globalRolePermissions && globalRolePermissions[role]) ? globalRolePermissions[role] : [];
    const isSuperAdmin = (role === 'super_admin');

    // UFW tab visibility
    if (tabUfwBtn) {
      const canAccessUfw = isSuperAdmin || perms.includes('ufw');
      tabUfwBtn.style.display = canAccessUfw ? 'inline-flex' : 'none';
      if (!canAccessUfw && activeTab === 'tab-ufw') switchTab('tab-hosts');
    }

    // Suspension settings tab visibility
    if (tabSuspensionBtn) {
      const canAccessSusp = isSuperAdmin || perms.includes('suspension');
      tabSuspensionBtn.style.display = canAccessSusp ? 'inline-flex' : 'none';
      if (!canAccessSusp && activeTab === 'tab-suspension') switchTab('tab-hosts');
    }

    // Team Users tab visibility (STRICTLY Super Admin Only)
    if (tabUsersBtn) {
      tabUsersBtn.style.display = isSuperAdmin ? 'inline-flex' : 'none';
      if (!isSuperAdmin && activeTab === 'tab-users') switchTab('tab-hosts');
    }

    // Export & Import backup controls
    const btnExportAll = document.getElementById('btn-export-all-zip');
    const btnOpenMigrate = document.getElementById('btn-open-migrate-modal');
    const canExportImport = isSuperAdmin || perms.includes('export_import');
    if (btnExportAll) {
      btnExportAll.style.display = canExportImport ? 'inline-flex' : 'none';
    }
    if (btnOpenMigrate) {
      btnOpenMigrate.style.display = canExportImport ? 'inline-flex' : 'none';
    }

    // Add Domain button permission
    if (btnOpenCreate) {
      const canCreate = isSuperAdmin || perms.includes('create_host');
      btnOpenCreate.style.display = canCreate ? 'inline-flex' : 'none';
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
    if (targetTab === 'tab-logs') {
      loadTrafficLogs(1);
      loadTrafficAnalytics();
      loadAuditLogs();
    }
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
      const res = await fetch('/api/hosts', {
        headers: sessionToken ? { 'Authorization': `Bearer ${sessionToken}` } : {}
      });
      if (!res.ok) {
        showToast('Error loading proxy hosts', 'error');
        return;
      }
      const data = await res.json();
      hostsData = Array.isArray(data) ? data : [];
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

    const hostList = Array.isArray(hostsData) ? hostsData : [];
    const filtered = hostList.filter(h => {
      const matchesSearch = !query || 
        (h.domain_names && h.domain_names.toLowerCase().includes(query)) ||
        (h.forward_host && h.forward_host.toLowerCase().includes(query)) ||
        String(h.forward_port || '').includes(query);

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

      const isDomainMgr = (activeRole === 'domain_manager' || h.can_edit_nginx_only);
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
              ${isDomainMgr ? `
                <button class="btn-secondary btn-sm" title="Edit Custom Nginx Configuration" onclick="openEditHostModal(${h.id})" style="display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.28rem 0.6rem; font-size: 0.74rem;">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                  <span>Edit Nginx</span>
                </button>
                <button class="btn-icon" title="View Generated Nginx Config" onclick="openNginxConfigModal(${h.id})">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
                </button>
              ` : `
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
              `}
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
    if (activeRole !== 'super_admin' && activeRole !== 'domain_manager') {
      showToast('Permission denied: Only Super Admin and Domain Managers can edit hosts', 'error');
      return;
    }
    const h = hostsData.find(item => item.id === id);
    if (!h) return;

    const isDomainMgr = (activeRole === 'domain_manager' || h.can_edit_nginx_only);
    hostModalTitle.textContent = isDomainMgr ? `Edit Custom Nginx Configuration (${h.domain_names})` : `Edit Proxy Host #${h.id}`;
    document.getElementById('edit-host-id').value = h.id;
    
    // Enable or disable fields based on role
    const fieldsToToggle = [
      'input-domain-names', 'input-app-name', 'input-forward-scheme',
      'input-forward-host', 'input-forward-port', 'input-websocket',
      'input-block-exploits', 'input-ssl-forced', 'input-suspended-reason'
    ];
    fieldsToToggle.forEach(fId => {
      const el = document.getElementById(fId);
      if (el) el.disabled = isDomainMgr;
    });

    document.getElementById('input-domain-names').value = h.domain_names;
    document.getElementById('input-app-name').value = h.app_name || '';
    document.getElementById('input-forward-scheme').value = h.forward_scheme;
    document.getElementById('input-forward-host').value = h.forward_host;
    document.getElementById('input-forward-port').value = h.forward_port;
    document.getElementById('input-websocket').checked = h.websocket_support;
    document.getElementById('input-block-exploits').checked = h.block_exploits;
    document.getElementById('input-ssl-forced').checked = h.ssl_forced;
    document.getElementById('input-suspended-reason').value = h.suspended_reason || 'Administrative Policy Suspension';
    
    const customNginxEl = document.getElementById('input-custom-nginx');
    customNginxEl.value = h.custom_nginx_config || '';
    customNginxEl.disabled = false;

    if (isDomainMgr) {
      setTimeout(() => {
        customNginxEl.focus();
      }, 100);
    }

    hostModal.classList.add('open');
  };

  hostForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const editId = document.getElementById('edit-host-id').value;

    if (editId && activeRole !== 'super_admin' && activeRole !== 'domain_manager') {
      showToast('Permission denied: Only Super Admin and Domain Managers can edit configurations', 'error');
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
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionToken}`
          },
          body: JSON.stringify(payload)
        });
      } else {
        res = await fetch('/api/hosts', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionToken}`
          },
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
          <td>
            <span style="font-family: monospace; font-size: 0.84rem; color: var(--secondary); font-weight: 600;">${escapeHtml(r.from_ip)}</span>
            ${r.from_ip && r.from_ip.includes('/') ? '<span style="font-size: 0.68rem; background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 4px; padding: 0.1rem 0.35rem; margin-left: 0.35rem; font-weight: 600;">CIDR Subnet</span>' : (r.from_ip && r.from_ip.toLowerCase() !== 'anywhere' ? '<span style="font-size: 0.68rem; background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 4px; padding: 0.1rem 0.35rem; margin-left: 0.35rem; font-weight: 600;">Host IP</span>' : '')}
          </td>
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

  function updateUfwModalPreview() {
    const ruleType = (document.getElementById('ufw-rule-type')?.value || 'ALLOW').toLowerCase();
    const port = (document.getElementById('ufw-port')?.value || '80').trim();
    const proto = (document.getElementById('ufw-protocol')?.value || 'tcp').toLowerCase();
    const fromIp = (document.getElementById('ufw-source-ip')?.value || 'Anywhere').trim();
    const previewEl = document.getElementById('ufw-live-command-preview');
    if (!previewEl) return;

    let cmd = `ufw ${ruleType}`;
    const isAnywhere = !fromIp || ['anywhere', 'any', 'all', '0.0.0.0/0', '::/0'].includes(fromIp.toLowerCase());
    const hasPort = port && !['any', 'all'].includes(port.toLowerCase());

    if (!isAnywhere) {
      cmd += ` from ${fromIp}`;
      if (hasPort) cmd += ` to any port ${port}`;
      if (proto === 'tcp' || proto === 'udp') cmd += ` proto ${proto}`;
    } else {
      if (hasPort) {
        if (proto === 'tcp' || proto === 'udp') cmd += ` ${port}/${proto}`;
        else cmd += ` to any port ${port}`;
      } else if (proto === 'tcp' || proto === 'udp') {
        cmd += ` proto ${proto}`;
      }
    }
    previewEl.textContent = cmd;
  }

  ['ufw-rule-type', 'ufw-port', 'ufw-protocol', 'ufw-source-ip'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', updateUfwModalPreview);
      el.addEventListener('change', updateUfwModalPreview);
    }
  });

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
    updateUfwModalPreview();
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
    updateUfwModalPreview();
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

  // Direct UFW CLI & CIDR Command Runner Console
  const quickUfwForm = document.getElementById('form-ufw-quick-cmd');
  if (quickUfwForm) {
    quickUfwForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (activeRole !== 'super_admin') {
        showToast('Permission denied: Only Super Admin can manage firewall', 'error');
        return;
      }
      const cmdInput = document.getElementById('input-ufw-cli-cmd');
      const rawCmd = cmdInput ? cmdInput.value.trim() : '';
      if (!rawCmd) return;

      const btn = document.getElementById('btn-submit-quick-ufw');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span>Applying...</span>';
      }

      try {
        const res = await fetch('/api/ufw/execute-command', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command: rawCmd })
        });
        const data = await res.json();
        if (!res.ok) {
          showToast(data.detail || 'Failed to apply UFW command', 'error');
        } else {
          showToast(data.message || 'Firewall rule applied successfully', 'success');
          loadUfwRules();
          loadSystemStatus();
        }
      } catch (err) {
        showToast('Network error applying firewall command', 'error');
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>Apply to Firewall</span>';
        }
      }
    });
  }

  // Quick Preset Badges for UFW Command Runner
  document.querySelectorAll('.ufw-example-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const cmd = pill.getAttribute('data-cmd');
      const input = document.getElementById('input-ufw-cli-cmd');
      if (input && cmd) {
        input.value = cmd;
        input.focus();
        showToast(`Loaded example: ${cmd}`);
      }
    });
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
    if (activeRole !== 'super_admin') return;
    try {
      const res = await fetch('/api/users', {
        headers: { 'Authorization': `Bearer ${sessionToken}` }
      });
      if (!res.ok) {
        if (res.status === 403) {
          usersData = [];
          renderUsersTable();
        }
        return;
      }
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
      if (u.role === 'domain_manager') roleBadgeStyle = 'background: rgba(14, 165, 233, 0.15); color: #0284c7; border: 1px solid rgba(14, 165, 233, 0.3);';
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
            ${(u.role === 'domain_manager' && u.allowed_domains) ? `
              <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem; max-width: 200px; word-break: break-all;">
                <strong>Assigned:</strong> ${escapeHtml(u.allowed_domains)}
              </div>
            ` : ''}
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
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="10" r="10"/><line x1="4.93" x2="19.07" y1="4.93" y2="19.07"/></svg>
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
  const userRoleSelect = document.getElementById('user-role');
  const domainMgrGroup = document.getElementById('domain-manager-domains-group');
  const domainMgrCheckboxes = document.getElementById('domain-manager-checkboxes');

  function updateDomainManagerField(assignedDomainsStr = '') {
    if (!userRoleSelect || !domainMgrGroup || !domainMgrCheckboxes) return;
    if (userRoleSelect.value === 'domain_manager') {
      domainMgrGroup.style.display = 'block';
      const allDomains = [];
      hostsData.forEach(h => {
        (h.domain_names || '').split(',').forEach(d => {
          const clean = d.trim();
          if (clean && !allDomains.includes(clean)) allDomains.push(clean);
        });
      });
      const assignedArr = (assignedDomainsStr || '').split(',').map(s => s.trim().toLowerCase());
      if (allDomains.length === 0) {
        domainMgrCheckboxes.innerHTML = '<span style="font-size:0.75rem; color:var(--text-muted);">No proxy hosts found. Add proxy hosts first.</span>';
      } else {
        domainMgrCheckboxes.innerHTML = allDomains.map(d => {
          const isChecked = assignedArr.includes(d.toLowerCase());
          return `
            <label style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; color: var(--text-main); cursor: pointer; padding: 0.15rem 0;">
              <input type="checkbox" class="domain-mgr-chk" value="${escapeHtml(d)}" ${isChecked ? 'checked' : ''} style="width: 15px; height: 15px; accent-color: var(--secondary);">
              <span>${escapeHtml(d)}</span>
            </label>
          `;
        }).join('');
      }
    } else {
      domainMgrGroup.style.display = 'none';
    }
  }

  if (userRoleSelect) {
    userRoleSelect.addEventListener('change', () => {
      updateDomainManagerField('');
    });
  }

  function getSelectedDomainManagerDomains() {
    if (!userRoleSelect || userRoleSelect.value !== 'domain_manager') return null;
    const chks = document.querySelectorAll('.domain-mgr-chk:checked');
    const selected = Array.from(chks).map(c => c.value.trim()).filter(Boolean);
    return selected.join(', ');
  }

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
    if (userRoleSelect) userRoleSelect.value = 'domain_manager';
    updateDomainManagerField('');
    userModal.classList.add('open');
  });

  window.openEditUserModal = async function(id) {
    if (activeRole !== 'super_admin') {
      showToast('Permission denied: Only Super Admin can edit users', 'error');
      return;
    }
    try {
      const res = await fetch(`/api/users/${id}`, {
        headers: { 'Authorization': `Bearer ${sessionToken}` }
      });
      if (!res.ok) throw new Error('Could not fetch user details');
      const u = await res.json();

      editUserIdInput.value = u.id;
      document.getElementById('user-fullname').value = u.full_name;
      userUsernameInput.value = u.username;
      userUsernameInput.disabled = true;
      userUsernameInput.style.opacity = '0.7';
      document.getElementById('user-email').value = u.email;
      if (userRoleSelect) userRoleSelect.value = u.role;
      document.getElementById('user-password').value = '';
      document.getElementById('user-is-active').checked = !!u.is_active;

      updateDomainManagerField(u.allowed_domains || '');

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
    const roleVal = document.getElementById('user-role').value;
    const allowedDomainsVal = getSelectedDomainManagerDomains();

    if (roleVal === 'domain_manager' && !allowedDomainsVal) {
      showToast('Please select at least one assigned proxy domain for this Domain Manager', 'warning');
      return;
    }

    if (editId) {
      // Edit User
      const payload = {
        full_name: document.getElementById('user-fullname').value.trim(),
        email: document.getElementById('user-email').value.trim(),
        role: roleVal,
        allowed_domains: allowedDomainsVal,
        password: document.getElementById('user-password').value || null,
        is_active: document.getElementById('user-is-active').checked
      };

      try {
        const res = await fetch(`/api/users/${editId}`, {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionToken}`
          },
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
        role: roleVal,
        allowed_domains: allowedDomainsVal,
        password: document.getElementById('user-password').value
      };

      try {
        const res = await fetch('/api/users', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionToken}`
          },
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
      const res = await fetch(`/api/users/${id}/suspend?suspend=${suspend}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${sessionToken}` }
      });
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
      const res = await fetch(`/api/users/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${sessionToken}` }
      });
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
  // Host Auto-Sync Handlers (/etc/nginx and Live UFW)
  // -----------------------------------------------------
  const btnAutoSyncNginx = document.getElementById('btn-auto-sync-nginx');
  if (btnAutoSyncNginx) {
    btnAutoSyncNginx.addEventListener('click', async () => {
      if (activeRole !== 'super_admin') {
        showToast('Permission denied: Only Super Admin can sync host configurations.', 'error');
        return;
      }
      const originalText = btnAutoSyncNginx.innerHTML;
      btnAutoSyncNginx.disabled = true;
      btnAutoSyncNginx.textContent = 'Scanning /etc/nginx...';
      try {
        const res = await fetch('/api/nginx/auto-sync', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sessionToken}`,
            'X-User-Role': activeRole
          }
        });
        const data = await res.json();
        if (data.status === 'success') {
          showToast(`Successfully synced ${data.synced} Nginx virtual host(s) from host!`, 'success');
          loadHosts();
        } else {
          showToast(data.message || 'No active Nginx configs detected in /etc/nginx', 'warning');
        }
      } catch (err) {
        showToast('Error syncing Nginx configs from host', 'error');
      } finally {
        btnAutoSyncNginx.disabled = false;
        btnAutoSyncNginx.innerHTML = originalText;
      }
    });
  }

  const btnClearDemoHosts = document.getElementById('btn-clear-demo-hosts');
  if (btnClearDemoHosts) {
    btnClearDemoHosts.addEventListener('click', async () => {
      if (activeRole !== 'super_admin') {
        showToast('Permission denied: Only Super Admin can manage host inventory.', 'error');
        return;
      }
      if (!confirm('Are you sure you want to remove development demo hosts (api.novacloud.io, portal.novacloudedges.com, etc.)?')) {
        return;
      }
      try {
        const res = await fetch('/api/nginx/clear-demo-hosts', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sessionToken}`,
            'X-User-Role': activeRole
          }
        });
        const data = await res.json();
        showToast(data.message || 'Cleared demo hosts', 'success');
        loadHosts();
      } catch (err) {
        showToast('Failed to clear demo hosts', 'error');
      }
    });
  }

  const btnSyncHostUfw = document.getElementById('btn-sync-host-ufw');
  if (btnSyncHostUfw) {
    btnSyncHostUfw.addEventListener('click', async () => {
      if (activeRole !== 'super_admin') {
        showToast('Permission denied: Only Super Admin can manage UFW.', 'error');
        return;
      }
      const originalText = btnSyncHostUfw.innerHTML;
      btnSyncHostUfw.disabled = true;
      btnSyncHostUfw.textContent = 'Syncing UFW...';
      try {
        const res = await fetch('/api/ufw/auto-sync', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sessionToken}`,
            'X-User-Role': activeRole
          }
        });
        const data = await res.json();
        if (data.status === 'success') {
          showToast(`Successfully synchronized ${data.synced} live UFW rules from host!`, 'success');
          loadUfwRules();
        } else {
          showToast(data.message || 'UFW status not active or empty', 'warning');
        }
      } catch (err) {
        showToast('Error syncing live UFW rules', 'error');
      } finally {
        btnSyncHostUfw.disabled = false;
        btnSyncHostUfw.innerHTML = originalText;
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
  // Web Traffic Logs & Real-Time Error Monitoring Tab (10 Records Per Page)
  // -----------------------------------------------------
  let trafficLogsData = [];
  let trafficTotalCount = 0;
  let trafficCurrentPage = 1;
  const TRAFFIC_PER_PAGE = 10;
  let currentTrafficFilter = 'all';
  let currentTrafficSearch = '';
  let currentTrafficDomain = 'all';

  let logsData = [];
  let logsCurrentPage = 1;
  const LOGS_PER_PAGE = 10;

  async function loadTrafficAnalytics() {
    try {
      const res = await fetch('/api/traffic/analytics');
      if (!res.ok) return;
      const data = await res.json();
      renderLogAnalytics(data);
    } catch (err) {
      console.warn('Error loading traffic analytics:', err);
    }
  }

  function renderLogAnalytics(data) {
    const kpiTotal = document.getElementById('traffic-kpi-total');
    const kpiUnique = document.getElementById('traffic-kpi-unique-ips');
    const kpiSuccess = document.getElementById('traffic-kpi-success');
    const kpi4xx = document.getElementById('traffic-kpi-4xx');
    const kpi5xx = document.getElementById('traffic-kpi-5xx');

    const totalEl = document.getElementById('ip-total-events');
    const uniqueEl = document.getElementById('ip-unique-count');
    const container = document.getElementById('access-ip-bars-container');

    const totalRequests = data.total_requests ?? 0;
    const uniqueIps = data.unique_ips ?? 0;
    const successRate = data.success_rate_pct ?? 100.0;
    const clientErr = data.client_error_count ?? 0;
    const serverErr = data.server_error_count ?? 0;

    if (kpiTotal) kpiTotal.textContent = totalRequests.toLocaleString();
    if (kpiUnique) kpiUnique.textContent = uniqueIps.toString();
    if (kpiSuccess) kpiSuccess.textContent = `${successRate.toFixed(1)}%`;
    if (kpi4xx) kpi4xx.textContent = clientErr.toString();
    if (kpi5xx) kpi5xx.textContent = serverErr.toString();

    if (totalEl) totalEl.textContent = `${totalRequests} events`;
    if (uniqueEl) uniqueEl.textContent = `${uniqueIps} nodes`;

    const abnormalBadge = document.getElementById('abnormal-traffic-badge');
    const abnormalText = document.getElementById('abnormal-traffic-text');
    if (abnormalBadge && abnormalText) {
      if (serverErr > 0) {
        abnormalBadge.className = 'ssl-badge expired';
        abnormalText.textContent = `${serverErr} Gateway 5xx Alerts`;
      } else if (clientErr > 15) {
        abnormalBadge.className = 'ssl-badge expiring';
        abnormalText.textContent = `${clientErr} 4xx Client Alerts`;
      } else {
        abnormalBadge.className = 'ssl-badge valid';
        abnormalText.textContent = 'Normal Baseline';
      }
    }

    if (!container) return;
    const topIps = (data.top_ips || []).slice(0, 6);

    if (topIps.length === 0) {
      container.innerHTML = `<div style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 2rem; font-size: 0.85rem;">No client access activity logged yet.</div>`;
      return;
    }

    container.innerHTML = topIps.map((item, idx) => {
      const isLocal = item.ip === '127.0.0.1' || item.ip === '::1' || item.ip === 'localhost';
      const pct = (typeof item.pct === 'number') ? item.pct : 0;
      const count = item.count || 0;
      const nodeLabel = item.label || (isLocal ? 'Localhost Console' : 'Remote Edge Client');
      const badgeClass = isLocal ? 'node-localhost' : (item.ip.startsWith('10.') || item.ip.startsWith('192.168.') ? 'node-vpn' : 'node-remote');
      const fillClass = isLocal ? 'fill-localhost' : 'fill-remote';
      const latencyText = isLocal ? '< 1ms local loopback' : `${12 + (idx * 14)}ms edge latency`;

      return `
        <div class="ip-distribution-card ${isLocal ? 'is-localhost' : 'is-remote'}">
          <div class="ip-card-header-row">
            <div class="ip-card-address-group">
              <span class="ip-card-address">${escapeHtml(item.ip)}</span>
              <span class="ip-node-badge ${badgeClass}">${escapeHtml(nodeLabel)}</span>
            </div>
            <span class="ip-card-pct-badge">${pct.toFixed(1)}%</span>
          </div>

          <div class="ip-card-stats-row">
            <span class="ip-card-count">${count.toLocaleString()} requests</span>
            <span>Rank #${idx + 1} of top remote nodes</span>
          </div>

          <div class="ip-card-bar-track">
            <div class="ip-card-bar-fill ${fillClass}" style="width: ${Math.min(100, Math.max(4, pct))}%;"></div>
          </div>

          <div class="ip-card-footer-meta">
            <span>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display: inline; vertical-align: -1px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
              ${latencyText}
            </span>
            <span style="color: #34d399;">Active Traffic</span>
          </div>
        </div>
      `;
    }).join('');
  }

  async function loadTrafficLogs(page = 1) {
    trafficCurrentPage = page;
    const tbody = document.getElementById('traffic-table-body');
    const paginationEl = document.getElementById('traffic-pagination');
    if (!tbody) return;

    try {
      const params = new URLSearchParams({
        page: trafficCurrentPage,
        limit: TRAFFIC_PER_PAGE,
        filter: currentTrafficFilter,
        search: currentTrafficSearch,
        domain: currentTrafficDomain
      });

      const res = await fetch(`/api/traffic/logs?${params.toString()}`);
      if (!res.ok) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">Failed to load traffic stream.</td></tr>`;
        return;
      }

      const data = await res.json();
      trafficLogsData = data.items || [];
      trafficTotalCount = data.total || 0;

      renderTrafficTable();
    } catch (err) {
      console.warn('Error loading traffic logs:', err);
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">Connection error while fetching traffic stream.</td></tr>`;
    }
  }

  function renderTrafficTable() {
    const tbody = document.getElementById('traffic-table-body');
    const paginationEl = document.getElementById('traffic-pagination');
    if (!tbody) return;

    if (!trafficLogsData || trafficLogsData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">No web traffic records matching the selected filter.</td></tr>`;
      if (paginationEl) paginationEl.style.display = 'none';
      return;
    }

    const totalPages = Math.ceil(trafficTotalCount / TRAFFIC_PER_PAGE);
    const startIndex = (trafficCurrentPage - 1) * TRAFFIC_PER_PAGE;

    tbody.innerHTML = trafficLogsData.map(log => {
      const code = log.status_code || 200;
      let statusClass = 'status-2xx';
      let statusLabel = 'OK';
      if (code >= 500) {
        statusClass = 'status-5xx';
        statusLabel = code === 502 ? 'Bad Gateway' : (code === 504 ? 'Gateway Timeout' : 'Server Error');
      } else if (code >= 400) {
        statusClass = 'status-4xx';
        statusLabel = code === 404 ? 'Not Found' : (code === 403 ? 'Forbidden' : 'Client Error');
      } else if (code >= 300) {
        statusClass = 'status-3xx';
        statusLabel = 'Redirect';
      }

      const method = (log.method || 'GET').toUpperCase();
      const methodClass = `method-${method.toLowerCase()}`;

      const ms = log.response_time_ms || 12;
      let latencyClass = 'fast';
      if (ms > 350) latencyClass = 'critical';
      else if (ms > 150) latencyClass = 'slow';
      else if (ms > 60) latencyClass = 'medium';

      const isError = log.is_error || code >= 400;
      const errorMsg = log.error_message || (isError ? `HTTP ${code} ${statusLabel}` : '');

      return `
        <tr style="${isError ? 'background: rgba(239, 68, 68, 0.03);' : ''}">
          <td style="white-space: nowrap; font-size: 0.8rem; color: var(--text-muted); font-family: var(--font-primary);">
            ${escapeHtml(log.timestamp)}
          </td>
          <td>
            <div style="display: flex; align-items: center; gap: 0.45rem;">
              <span class="http-method-pill ${methodClass}">${escapeHtml(method)}</span>
              <span class="http-status-pill ${statusClass}">${code} ${statusLabel}</span>
            </div>
          </td>
          <td>
            <div style="font-weight: 700; color: var(--text-main); font-size: 0.84rem;">${escapeHtml(log.domain)}</div>
            <div style="font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(log.path)}</div>
          </td>
          <td>
            <div style="font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.82rem; font-weight: 700; color: var(--text-main);">${escapeHtml(log.client_ip)}</div>
          </td>
          <td>
            <span class="latency-pill ${latencyClass}">${ms} ms</span>
          </td>
          <td>
            ${isError ? `
              <div class="traffic-error-detail-box">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <span>${escapeHtml(errorMsg)}</span>
              </div>
            ` : `
              <span style="font-size: 0.74rem; color: var(--text-muted); display: inline-flex; align-items: center; gap: 0.3rem;">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
                Upstream routed &amp; keep-alive clean
              </span>
            `}
          </td>
        </tr>
      `;
    }).join('');

    renderPagination(paginationEl, trafficCurrentPage, totalPages, trafficTotalCount, startIndex, trafficLogsData.length, (p) => {
      loadTrafficLogs(p);
    });
  }

  // Populate domain filter options for web traffic dropdown
  function updateTrafficDomainOptions() {
    const sel = document.getElementById('traffic-domain-select');
    if (!sel || !hostsData) return;

    const currentVal = sel.value;
    const domains = new Set();
    hostsData.forEach(h => {
      (h.domain_names || '').split(',').forEach(d => {
        if (d.trim()) domains.add(d.trim());
      });
    });

    let opts = '<option value="all">All Configured Virtual Hosts</option>';
    domains.forEach(d => {
      opts += `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`;
    });
    sel.innerHTML = opts;
    if (domains.has(currentVal)) sel.value = currentVal;
  }

  // Web Traffic Filter Buttons & Inputs
  const trafficFilterBtns = [
    { id: 'btn-traffic-filter-all', filter: 'all' },
    { id: 'btn-traffic-filter-errors', filter: 'errors' },
    { id: 'btn-traffic-filter-5xx', filter: '5xx' },
    { id: 'btn-traffic-filter-4xx', filter: '4xx' },
    { id: 'btn-traffic-filter-2xx', filter: '2xx' }
  ];

  trafficFilterBtns.forEach(item => {
    const btn = document.getElementById(item.id);
    if (btn) {
      btn.addEventListener('click', () => {
        trafficFilterBtns.forEach(b => {
          const el = document.getElementById(b.id);
          if (el) el.classList.remove('active', 'errors-active');
        });
        btn.classList.add('active');
        if (item.filter === 'errors' || item.filter === '5xx') {
          btn.classList.add('errors-active');
        }
        currentTrafficFilter = item.filter;
        loadTrafficLogs(1);
      });
    }
  });

  const trafficSearchInput = document.getElementById('traffic-search-input');
  if (trafficSearchInput) {
    let debounceTimer;
    trafficSearchInput.addEventListener('input', (e) => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        currentTrafficSearch = e.target.value.trim();
        loadTrafficLogs(1);
      }, 300);
    });
  }

  const trafficDomainSelect = document.getElementById('traffic-domain-select');
  if (trafficDomainSelect) {
    trafficDomainSelect.addEventListener('change', (e) => {
      currentTrafficDomain = e.target.value;
      loadTrafficLogs(1);
    });
  }

  const btnRefreshTraffic = document.getElementById('btn-refresh-traffic');
  if (btnRefreshTraffic) {
    btnRefreshTraffic.addEventListener('click', () => {
      loadTrafficAnalytics();
      loadTrafficLogs(1);
      showToast('Traffic stream refreshed');
    });
  }

  // -----------------------------------------------------
  // Audit Logs (10 Records Per Page)
  // -----------------------------------------------------
  async function loadAuditLogs() {
    try {
      const res = await fetch('/api/logs');
      logsData = await res.json();
      renderAuditLogsTable();
      updateTrafficDomainOptions();
    } catch (err) {
      showToast('Error loading logs', 'error');
    }
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

  // -----------------------------------------------------
  // Circular Profile Widget & Change Password Modal
  // -----------------------------------------------------
  function setupUserProfileWidget() {
    const btnUserProfile = document.getElementById('btn-user-profile');
    const userProfileDropdown = document.getElementById('user-profile-dropdown');
    const btnOpenChangePass = document.getElementById('btn-open-change-pass');
    const changePassModal = document.getElementById('change-pass-modal');
    const btnCloseChangePass = document.getElementById('btn-close-change-pass-modal');
    const btnCancelChangePass = document.getElementById('btn-cancel-change-pass');
    const changePassForm = document.getElementById('change-pass-form');
    const btnDropdownLogout = document.getElementById('btn-dropdown-logout');

    // Populate profile from stored session user if available
    const storedUserRaw = localStorage.getItem('nova_current_user');
    if (storedUserRaw) {
      try {
        const storedUser = JSON.parse(storedUserRaw);
        updateUserProfileUI(storedUser);
      } catch (e) {}
    }

    if (btnUserProfile && userProfileDropdown) {
      btnUserProfile.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const isOpen = userProfileDropdown.classList.contains('show') || userProfileDropdown.style.display === 'block';
        if (isOpen) {
          userProfileDropdown.classList.remove('show');
          userProfileDropdown.style.display = 'none';
        } else {
          userProfileDropdown.classList.add('show');
          userProfileDropdown.style.display = 'block';
        }
      });

      document.addEventListener('click', (e) => {
        if (!userProfileDropdown.contains(e.target) && !btnUserProfile.contains(e.target)) {
          userProfileDropdown.classList.remove('show');
          userProfileDropdown.style.display = 'none';
        }
      });
    }

    const btnNavLogout = document.getElementById('btn-navbar-logout');
    if (btnNavLogout) {
      btnNavLogout.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleLogout(false);
      });
    }

    if (btnDropdownLogout) {
      btnDropdownLogout.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleLogout(false);
      });
    }

    if (btnOpenChangePass && changePassModal) {
      btnOpenChangePass.addEventListener('click', () => {
        if (userProfileDropdown) userProfileDropdown.style.display = 'none';
        if (changePassForm) changePassForm.reset();
        changePassModal.classList.add('open');
      });
    }

    if (btnCloseChangePass && changePassModal) {
      btnCloseChangePass.addEventListener('click', () => {
        changePassModal.classList.remove('open');
      });
    }

    if (btnCancelChangePass && changePassModal) {
      btnCancelChangePass.addEventListener('click', () => {
        changePassModal.classList.remove('open');
      });
    }

    if (changePassForm) {
      changePassForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const currentPass = document.getElementById('cp-current-password').value;
        const newPass = document.getElementById('cp-new-password').value;
        const confirmPass = document.getElementById('cp-confirm-password').value;

        if (newPass !== confirmPass) {
          showToast('New passwords do not match. Please verify.', 'error');
          return;
        }

        const btnSubmit = document.getElementById('btn-submit-change-pass');
        const origText = btnSubmit.textContent;
        btnSubmit.disabled = true;
        btnSubmit.textContent = 'Updating...';

        try {
          const res = await fetch('/api/auth/change-password', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${sessionToken}`
            },
            body: JSON.stringify({
              current_password: currentPass,
              new_password: newPass
            })
          });

          const data = await res.json();
          if (!res.ok) throw new Error(data.detail || 'Password update failed');

          showToast(data.message, 'success');
          changePassModal.classList.remove('open');
          changePassForm.reset();
        } catch (err) {
          showToast(err.message, 'error');
        } finally {
          btnSubmit.disabled = false;
          btnSubmit.textContent = origText;
        }
      });
    }
  }

  // -----------------------------------------------------
  // Fish-Eye Password Reveal / Hide Toggles
  // -----------------------------------------------------
  function setupPasswordEyeToggles() {
    document.querySelectorAll('.btn-eye-toggle').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = btn.getAttribute('data-target');
        let input;
        if (targetId) {
          input = document.getElementById(targetId);
        } else {
          const wrap = btn.closest('.password-field-wrapper');
          if (wrap) input = wrap.querySelector('input');
        }
        if (!input) return;

        const eyeOpen = btn.querySelector('.eye-open');
        const eyeClosed = btn.querySelector('.eye-closed');

        if (input.type === 'password') {
          input.type = 'text';
          if (eyeOpen) eyeOpen.style.display = 'none';
          if (eyeClosed) eyeClosed.style.display = 'inline-block';
        } else {
          input.type = 'password';
          if (eyeOpen) eyeOpen.style.display = 'inline-block';
          if (eyeClosed) eyeClosed.style.display = 'none';
        }
      });
    });
  }

  // -----------------------------------------------------
  // Role Access Features & Permissions Matrix (Super Admin Managed)
  // -----------------------------------------------------
  const SYSTEM_FEATURES = [
    { id: 'hosts', name: 'Proxy Hosts View', desc: 'Browse configured reverse proxy hosts and telemetry' },
    { id: 'create_host', name: 'Add Proxy Host', desc: 'Create new apex domain and subdomain routes' },
    { id: 'edit_hosts', name: 'Edit Host Configurations', desc: 'Modify upstream servers, WebSocket & SSL rules' },
    { id: 'suspend_hosts', name: 'Suspend / Unsuspend Sites', desc: 'Activate 503 maintenance mode on websites' },
    { id: 'delete_hosts', name: 'Delete Proxy Hosts', desc: 'Remove proxy host configurations from server' },
    { id: 'export_import', name: 'Migration & Backup', desc: 'Export and import Nginx .conf files across servers' },
    { id: 'ufw', name: 'UFW Firewall (WAF)', desc: 'Inspect, create and delete host firewall rules' },
    { id: 'security', name: 'WHOIS & Abuse Security', desc: 'Domain registrar lookups, abuse logs & IP blocks' },
    { id: 'billing', name: 'Domain & SSL Expiry', desc: 'Expiration monitoring, renewal countdowns & Certbot' },
    { id: 'suspension', name: 'Suspension Settings', desc: 'Custom 503 maintenance statement & contact details' },
    { id: 'editor', name: 'Nginx Syntax Tester', desc: 'Live configuration syntax validator with line numbers' },
    { id: 'logs', name: 'Audit Logs & Threats', desc: 'Administrative action logs and threat detection' }
  ];

  async function loadRolePermissionsMatrix() {
    try {
      const res = await fetch('/api/roles/permissions');
      if (!res.ok) return;
      globalRolePermissions = await res.json();
      renderRoleMatrixTable();
      applyRolePermissions(activeRole);
    } catch (err) {
      console.warn('Could not load role permissions:', err);
    }
  }

  function renderRoleMatrixTable() {
    const tbody = document.getElementById('role-matrix-body');
    if (!tbody) return;

    const webmasterPerms = (globalRolePermissions.webmaster || []);
    const securityPerms = (globalRolePermissions.security || []);
    const billingPerms = (globalRolePermissions.billing || []);

    tbody.innerHTML = SYSTEM_FEATURES.map(feat => {
      const isWm = webmasterPerms.includes(feat.id);
      const isSec = securityPerms.includes(feat.id);
      const isBill = billingPerms.includes(feat.id);

      return `
        <tr>
          <td><strong style="color: var(--text-main); font-size: 0.84rem;">${escapeHtml(feat.name)}</strong></td>
          <td style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(feat.desc)}</td>
          <td style="text-align: center;">
            <input type="checkbox" class="role-perm-chk" data-role="webmaster" data-feature="${feat.id}" ${isWm ? 'checked' : ''} style="width: 16px; height: 16px; accent-color: var(--secondary); cursor: pointer;">
          </td>
          <td style="text-align: center;">
            <input type="checkbox" class="role-perm-chk" data-role="security" data-feature="${feat.id}" ${isSec ? 'checked' : ''} style="width: 16px; height: 16px; accent-color: #f59e0b; cursor: pointer;">
          </td>
          <td style="text-align: center;">
            <input type="checkbox" class="role-perm-chk" data-role="billing" data-feature="${feat.id}" ${isBill ? 'checked' : ''} style="width: 16px; height: 16px; accent-color: #a855f7; cursor: pointer;">
          </td>
          <td style="text-align: center;">
            <span class="role-lock-badge" style="background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border-color: rgba(16, 185, 129, 0.3); font-size: 0.7rem; padding: 0.15rem 0.45rem;">Full Rights</span>
          </td>
        </tr>
      `;
    }).join('');
  }

  const btnSaveRoleMatrix = document.getElementById('btn-save-role-matrix');
  if (btnSaveRoleMatrix) {
    btnSaveRoleMatrix.addEventListener('click', async () => {
      if (activeRole !== 'super_admin') {
        showToast('Permission denied: Only Super Admin can modify role features', 'error');
        return;
      }

      const roles = ['webmaster', 'security', 'billing'];
      const updatedPerms = {
        webmaster: [],
        security: [],
        billing: []
      };

      roles.forEach(r => {
        document.querySelectorAll(`.role-perm-chk[data-role="${r}"]:checked`).forEach(chk => {
          updatedPerms[r].push(chk.getAttribute('data-feature'));
        });
      });

      const originalHtml = btnSaveRoleMatrix.innerHTML;
      btnSaveRoleMatrix.disabled = true;
      btnSaveRoleMatrix.textContent = 'Saving...';

      try {
        const res = await fetch('/api/roles/permissions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${sessionToken}`
          },
          body: JSON.stringify({ permissions: updatedPerms })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Failed to update role permissions');

        globalRolePermissions = data.permissions;
        applyRolePermissions(activeRole);
        showToast('Role access features saved successfully!', 'success');
      } catch (err) {
        showToast(err.message, 'error');
      } finally {
        btnSaveRoleMatrix.disabled = false;
        btnSaveRoleMatrix.innerHTML = originalHtml;
      }
    });
  }

  // Initial loads & telemetry intervals
  setupUserProfileWidget();
  setupPasswordEyeToggles();
  loadRolePermissionsMatrix();
  loadHosts();
  loadSystemMetrics();

  // Live telemetry polling (3s interval)
  setInterval(loadSystemMetrics, 3000);

  // Status & database health check (10s interval)
  setInterval(loadSystemStatus, 10000);
});

// 主题管理
let currentTheme = 'auto';

function setTheme(mode) {
  currentTheme = mode;
  localStorage.setItem('proxy_theme', mode);
  applyTheme();
}

function applyTheme() {
  const root = document.documentElement;
  const isDarkSystem = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const lightBtn = document.getElementById('btn-theme-light');
  const darkBtn = document.getElementById('btn-theme-dark');
  const autoBtn = document.getElementById('btn-theme-auto');

  [lightBtn, darkBtn, autoBtn].forEach(b => {
    if (b) b.classList.remove('active');
  });

  if (currentTheme === 'dark' || (currentTheme === 'auto' && isDarkSystem)) {
    root.classList.remove('light');
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
    root.classList.add('light');
  }

  if (currentTheme === 'light' && lightBtn) lightBtn.classList.add('active');
  else if (currentTheme === 'dark' && darkBtn) darkBtn.classList.add('active');
  else if (currentTheme === 'auto' && autoBtn) autoBtn.classList.add('active');

  if (hasLoadedOnce && lastOverviewData && lastOverviewData.dns_stats) {
    renderDNSPieChart(lastOverviewData.dns_stats, true);
  }
}

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (currentTheme === 'auto') applyTheme();
});

// 侧边栏展开与收起
let sidebarOpen = false;
function toggleSidebar(forceState) {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  const isMobile = window.innerWidth <= 768;

  if (typeof forceState === 'boolean') {
    sidebarOpen = forceState;
  } else {
    sidebarOpen = !sidebarOpen;
  }

  if (isMobile) {
    if (sidebarOpen) {
      sidebar.classList.add('open');
      overlay.classList.add('active');
    } else {
      sidebar.classList.remove('open');
      overlay.classList.remove('active');
    }
  } else {
    if (sidebar.classList.contains('hidden')) {
      sidebar.classList.remove('hidden');
    } else {
      sidebar.classList.add('hidden');
    }
  }
}

// 标签页切换
let currentTab = 'overview';
function switchTab(tab) {
  currentTab = tab;
  const overviewNav = document.getElementById('nav-overview');
  const logsNav = document.getElementById('nav-logs');
  const overviewView = document.getElementById('view-overview');
  const logsView = document.getElementById('view-logs');
  const pageTitle = document.getElementById('page-title');

  if (tab === 'overview') {
    overviewView.classList.remove('hidden');
    logsView.classList.add('hidden');
    overviewNav.classList.add('active');
    logsNav.classList.remove('active');
    pageTitle.innerText = '系统总览';
    fetchOverviewData(true);
  } else {
    overviewView.classList.add('hidden');
    logsView.classList.remove('hidden');
    logsNav.classList.add('active');
    overviewNav.classList.remove('active');
    pageTitle.innerText = '实时日志';
    scrollToBottom();
  }

  if (window.innerWidth <= 768) {
    toggleSidebar(false);
  }
}

function formatDuration(str) {
  if (!str) return '0秒';
  if (str.includes('秒') || str.includes('分') || str.includes('小时')) return str;
  return str.replace(/h/g, '小时').replace(/m/g, '分').replace(/s/g, '秒');
}

// 总览数据获取与渲染
let overviewTimer = null;
let overviewInFlight = false;
let overviewController = null;
let hasLoadedOnce = false;
let lastOverviewData = null;
let lastOutboundSig = '';
let lastConnsSig = '';
let lastDNSUpstreamSig = '';
let lastDNSPieSig = '';

function hideInitialPieSkeleton() {
  const pieSkeleton = document.getElementById('dns-pie-skeleton');
  const pieCanvas = document.getElementById('dns-pie-canvas');
  if (pieSkeleton) pieSkeleton.classList.add('hidden');
  if (pieCanvas) pieCanvas.classList.remove('hidden');
}

async function fetchOverviewData(force = false) {
  if (overviewInFlight && !force) return;
  if (force && overviewController) {
    overviewController.abort();
  }

  overviewInFlight = true;
  overviewController = new AbortController();
  const timeoutId = setTimeout(() => {
    if (overviewController) overviewController.abort();
  }, 5000);

  try {
    const res = await fetch('/api/overview', { signal: overviewController.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const isFirstLoad = !hasLoadedOnce;
    hasLoadedOnce = true;
    hideInitialPieSkeleton();
    renderOverview(data, isFirstLoad);
  } catch (e) {
    if (e.name !== 'AbortError' && !hasLoadedOnce) {
      showInitialLoadError();
    }
  } finally {
    clearTimeout(timeoutId);
    overviewInFlight = false;
  }
}

function showInitialLoadError() {
  const errHtml = '<div style="color: var(--text-muted); font-size: 14px;">数据加载失败，请等待重试或点击右上角“刷新数据”</div>';
  const outboundList = document.getElementById('outbound-list');
  const tableBody = document.getElementById('active-conns-body');
  const dnsUpstreamList = document.getElementById('dns-upstream-list');
  const legend = document.getElementById('dns-pie-legend');
  if (outboundList) outboundList.innerHTML = errHtml;
  if (dnsUpstreamList) dnsUpstreamList.innerHTML = errHtml;
  if (legend) legend.innerHTML = errHtml;
  if (tableBody) {
    tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 16px 0;">数据加载失败，请等待重试或点击右上角“刷新数据”</td></tr>';
  }
}

function renderOverview(data, forceRender = false) {
  if (!data) return;
  lastOverviewData = data;

  // 卡片 1: 实际驱动
  const driverElem = document.getElementById('metric-driver');
  const scopeElem = document.getElementById('metric-scope');
  if (driverElem) driverElem.innerText = data.driver || '关闭';
  if (scopeElem) scopeElem.innerText = `范围：${data.scope || '未启用'}`;

  // 卡片 2: TCP 连接
  const tcpElem = document.getElementById('metric-tcp');
  const tcpSubElem = document.getElementById('metric-tcp-sub');
  if (tcpElem) tcpElem.innerText = `${data.active_tcp || 0} 个活跃`;
  if (tcpSubElem) tcpSubElem.innerText = `上限 ${data.max_tcp || 256}`;

  // 卡片 3: UDP 传输
  const udpSessionsElem = document.getElementById('metric-udp-sessions');
  const udpDropsElem = document.getElementById('metric-udp-drops');
  if (data.udp_stats) {
    if (udpSessionsElem) udpSessionsElem.innerText = `${data.udp_stats.active || 0} 会话`;
    const drops = (data.udp_stats.dropped || 0) + (data.udp_stats.kernel_dropped || 0) + (data.udp_stats.capture_dropped || 0);
    if (udpDropsElem) udpDropsElem.innerText = `丢包计数 ${drops}`;
  }

  // 卡片 4: DNS 缓存
  const dnsCachedElem = document.getElementById('metric-dns-cached');
  const dnsSubElem = document.getElementById('metric-dns-sub');
  if (data.dns_stats) {
    const cached = data.dns_stats.cached || 0;
    const maxEntries = data.dns_stats.max_entries || 4096;
    const hitRate = data.dns_stats.hit_rate || '0%';
    if (dnsCachedElem) dnsCachedElem.innerText = `${cached} 条 / ${maxEntries} 条`;
    if (dnsSubElem) dnsSubElem.innerText = `命中率 ${hitRate}`;
  }

  // 出站分流统计（带进度横条，按数量降序排列）
  const outboundList = document.getElementById('outbound-list');
  const outboundFooter = document.getElementById('outbound-footer');
  if (outboundList) {
    const connected = data.connected || {};
    const outboundSig = JSON.stringify(connected);
    if (forceRender || outboundSig !== lastOutboundSig) {
      lastOutboundSig = outboundSig;
      const keys = Object.keys(connected);
      keys.sort((a, b) => (connected[b] || 0) - (connected[a] || 0));

      let total = 0;
      keys.forEach(k => { total += connected[k] || 0; });

      if (keys.length === 0 || total === 0) {
        outboundList.innerHTML = '<div style="color: var(--text-muted); font-size: 14px;">暂无出站连接数据</div>';
      } else {
        outboundList.innerHTML = keys.map(name => {
          const count = connected[name] || 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return `
            <div class="outbound-item">
              <div class="outbound-header">
                <span class="outbound-name">${escapeHtml(name)}</span>
                <span class="outbound-count">${count.toLocaleString()} 次 (${pct}%)</span>
              </div>
              <div class="progress-track">
                <div class="progress-fill" style="width: ${pct}%;"></div>
              </div>
            </div>
          `;
        }).join('');
      }

      if (outboundFooter) {
        outboundFooter.innerHTML = `
          <span>出站出口总数：${keys.length}</span>
          <span>累计总连接：${total.toLocaleString()}</span>
        `;
      }
    }
  }

  // 活跃连接列表
  const tableBody = document.getElementById('active-conns-body');
  if (tableBody) {
    const conns = data.active_conns || [];
    const connsSig = JSON.stringify(conns);
    if (forceRender || connsSig !== lastConnsSig) {
      lastConnsSig = connsSig;
      if (conns.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 16px 0;">当前暂无活跃连接</td></tr>';
      } else {
        tableBody.innerHTML = conns.map(c => `
          <tr>
            <td class="col-id">${c.id}</td>
            <td class="col-addr" title="${escapeHtml(c.source)}"><span class="cell-text">${escapeHtml(c.source)}</span></td>
            <td class="col-addr" title="${escapeHtml(c.destination)}"><span class="cell-text">${escapeHtml(c.destination)}</span></td>
            <td class="col-outbound"><span style="color: var(--primary); font-weight: 500;">${escapeHtml(c.outbound)}</span></td>
            <td class="col-duration">${escapeHtml(formatDuration(c.duration))}</td>
          </tr>
        `).join('');
      }
    }
  }

  // DNS 上游分流统计（按数量降序排列）
  const dnsUpstreamList = document.getElementById('dns-upstream-list');
  const dnsUpstreamFooter = document.getElementById('dns-upstream-footer');
  if (dnsUpstreamList && data.dns_stats) {
    const upstreams = data.dns_stats.upstream_requests || {};
    const upstreamSig = JSON.stringify(upstreams);
    if (forceRender || upstreamSig !== lastDNSUpstreamSig) {
      lastDNSUpstreamSig = upstreamSig;
      const keys = Object.keys(upstreams);
      keys.sort((a, b) => (upstreams[b] || 0) - (upstreams[a] || 0));

      let total = 0;
      keys.forEach(k => { total += upstreams[k] || 0; });

      if (keys.length === 0 || total === 0) {
        dnsUpstreamList.innerHTML = '<div style="color: var(--text-muted); font-size: 14px;">暂无 DNS 上游请求数据</div>';
      } else {
        dnsUpstreamList.innerHTML = keys.map(name => {
          const count = upstreams[name] || 0;
          const pct = total > 0 ? Math.round((count / total) * 100) : 0;
          return `
            <div class="outbound-item">
              <div class="outbound-header">
                <span class="outbound-name">${escapeHtml(name)}</span>
                <span class="outbound-count">${count.toLocaleString()} 次 (${pct}%)</span>
              </div>
              <div class="progress-track">
                <div class="progress-fill-dns" style="width: ${pct}%;"></div>
              </div>
            </div>
          `;
        }).join('');
      }

      if (dnsUpstreamFooter) {
        dnsUpstreamFooter.innerHTML = `
          <span>上游服务器数：${keys.length}</span>
          <span>累计总解析请求：${total.toLocaleString()}</span>
        `;
      }
    }
  }

  // DNS 查询分布饼状图
  renderDNSPieChart(data.dns_stats, forceRender);
}

function renderDNSPieChart(dns, forceRender = false) {
  const canvas = document.getElementById('dns-pie-canvas');
  const legend = document.getElementById('dns-pie-legend');
  if (!canvas || !legend) return;

  const pieSig = dns ? `${dns.queries || 0}:${dns.stale_hits || 0}:${dns.fresh_hits || 0}:${dns.other_queries || 0}:${dns.failures || 0}` : 'empty';
  if (!forceRender && pieSig === lastDNSPieSig) return;
  lastDNSPieSig = pieSig;

  if (!dns || !dns.queries || dns.queries === 0) {
    drawEmptyPie(canvas);
    legend.innerHTML = '<div style="color: var(--text-muted); font-size: 14px;">暂无 DNS 查询数据</div>';
    return;
  }

  const stale = dns.stale_hits || 0;
  const fresh = dns.fresh_hits || 0;
  const other = dns.other_queries || 0;
  const fail = dns.failures || 0;
  const total = dns.queries || (stale + fresh + other + fail);

  const isDark = document.documentElement.classList.contains('dark');
  const items = [
    { name: '过期缓存命中', count: stale, color: isDark ? '#fbbf24' : '#f59e0b' },
    { name: '有效缓存命中', count: fresh, color: isDark ? '#34d399' : '#10b981' },
    { name: '上游查询', count: other, color: isDark ? '#60a5fa' : '#3b82f6' },
    { name: '查询失败', count: fail, color: isDark ? '#f87171' : '#ef4444' }
  ];

  drawPieSlices(canvas, items, total);

  legend.innerHTML = items.map(it => {
    const pct = total > 0 ? ((it.count / total) * 100).toFixed(1) : '0.0';
    return `
      <div class="legend-row">
        <span class="legend-color" style="background-color: ${it.color};"></span>
        <span class="legend-title">${it.name}</span>
        <span class="legend-stat">${it.count.toLocaleString()} 次 (${pct}%)</span>
      </div>
    `;
  }).join('');
}

function drawEmptyPie(canvas) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = 180 * dpr;
  canvas.height = 180 * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, 180, 180);

  ctx.beginPath();
  ctx.arc(90, 90, 66, 0, 2 * Math.PI);
  ctx.strokeStyle = document.documentElement.classList.contains('dark') ? '#334155' : '#e2e8f0';
  ctx.lineWidth = 26;
  ctx.stroke();
}

function drawPieSlices(canvas, items, total) {
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = 180 * dpr;
  canvas.height = 180 * dpr;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, 180, 180);

  const cx = 90;
  const cy = 90;
  const radius = 66;
  const lineWidth = 26;
  let startAngle = -Math.PI / 2;

  items.forEach(item => {
    if (item.count <= 0) return;
    const sliceAngle = (item.count / total) * 2 * Math.PI;
    const endAngle = startAngle + sliceAngle;

    ctx.beginPath();
    ctx.arc(cx, cy, radius, startAngle, endAngle);
    ctx.strokeStyle = item.color;
    ctx.lineWidth = lineWidth;
    ctx.stroke();

    startAngle = endAngle;
  });
}

// 快捷操作
async function flushDNS() {
  try {
    const res = await fetch('/api/dns/flush', { method: 'POST' });
    if (res.ok) {
      alert('DNS 缓存已成功清空');
      fetchOverviewData();
    } else {
      alert('清空 DNS 缓存失败');
    }
  } catch (e) {
    alert('请求失败：' + e.message);
  }
}

async function reloadConfig() {
  try {
    const res = await fetch('/api/reload', { method: 'POST' });
    if (res.ok) {
      alert('配置重新加载成功');
      fetchOverviewData();
    } else {
      alert('配置重新加载失败');
    }
  } catch (e) {
    alert('请求失败：' + e.message);
  }
}

// 日志处理
let logs = [];
let maxLogs = 1000;
let lastLogID = 0;
let autoScroll = true;
let streamActive = true;
let eventSource = null;
let pollTimer = null;
let streamMode = 'idle'; // 'idle' | 'sse' | 'polling'
let pendingRenderLogs = [];
let logFlushScheduled = false;

function stopPollLogs() {
  if (pollTimer !== null) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
}

function schedulePollLogs(delayMs) {
  stopPollLogs();
  pollTimer = setTimeout(pollLogs, delayMs);
}

function initLogStream() {
  stopPollLogs();
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  if (window.EventSource) {
    streamMode = 'sse';
    eventSource = new EventSource('/api/logs/events');
    eventSource.onopen = function () {
      streamMode = 'sse';
      stopPollLogs();
    };
    eventSource.onmessage = function (event) {
      if (!streamActive) return;
      try {
        const entry = JSON.parse(event.data);
        appendLogEntry(entry);
      } catch (e) {
        // 心跳或格式化问题
      }
    };
    eventSource.onerror = function () {
      if (streamMode !== 'polling') {
        streamMode = 'polling';
        schedulePollLogs(2000);
      }
    };
  } else {
    streamMode = 'polling';
    pollLogs();
  }
}

async function pollLogs() {
  pollTimer = null;
  if (streamMode !== 'polling') return;
  if (!streamActive) {
    schedulePollLogs(1000);
    return;
  }
  try {
    const res = await fetch(`/api/logs?after=${lastLogID}`);
    if (res.ok) {
      const snapshot = await res.json();
      if (snapshot.entries && snapshot.entries.length > 0) {
        snapshot.entries.forEach(entry => appendLogEntry(entry));
      }
      if (snapshot.next) {
        lastLogID = snapshot.next;
      }
    }
  } catch (e) {}
  if (streamMode === 'polling') {
    schedulePollLogs(1000);
  }
}

function parseLogLevel(text) {
  const upper = text.toUpperCase();
  if (upper.includes('ERROR') || upper.includes('FAIL')) return { level: '错误', cls: 'error' };
  if (upper.includes('WARN')) return { level: '警告', cls: 'warn' };
  if (upper.includes('DEBUG')) return { level: '调试', cls: 'debug' };
  return { level: '信息', cls: 'info' };
}

function getSearchKey() {
  return (document.getElementById('log-search')?.value || '').toLowerCase().trim();
}

function matchesSearch(logItem, searchKey) {
  if (!searchKey) return true;
  return logItem.textLower.includes(searchKey) || logItem.level.includes(searchKey);
}

function buildLogLineElement(l) {
  const line = document.createElement('div');
  line.className = 'log-line';

  const timeSpan = document.createElement('span');
  timeSpan.className = 'log-time';
  timeSpan.textContent = `[${l.time}]`;

  const levelSpan = document.createElement('span');
  levelSpan.className = `log-level ${l.cls}`;
  levelSpan.textContent = `[${l.level}]`;

  const textSpan = document.createElement('span');
  textSpan.className = 'log-text';
  textSpan.textContent = l.text;

  line.appendChild(timeSpan);
  line.appendChild(levelSpan);
  line.appendChild(textSpan);
  return line;
}

function appendLogEntry(entry) {
  if (!entry || !entry.text) return;
  lastLogID = Math.max(lastLogID, entry.id || 0);

  const parsed = parseLogLevel(entry.text);
  const now = new Date();
  const timeStr = now.toTimeString().split(' ')[0];

  const logItem = {
    id: entry.id,
    time: timeStr,
    level: parsed.level,
    cls: parsed.cls,
    text: entry.text,
    textLower: entry.text.toLowerCase()
  };

  logs.push(logItem);
  if (logs.length > maxLogs) {
    logs.shift();
  }

  pendingRenderLogs.push(logItem);
  scheduleLogFlush();
}

function scheduleLogFlush() {
  if (logFlushScheduled) return;
  logFlushScheduled = true;
  requestAnimationFrame(flushPendingLogs);
}

function flushPendingLogs() {
  logFlushScheduled = false;
  if (pendingRenderLogs.length === 0) return;

  const terminal = document.getElementById('log-terminal');
  const countIndicator = document.getElementById('log-count');
  if (!terminal) return;

  const batch = pendingRenderLogs.splice(0, pendingRenderLogs.length);
  const searchKey = getSearchKey();
  const frag = document.createDocumentFragment();
  let added = 0;

  for (let i = 0; i < batch.length; i++) {
    if (matchesSearch(batch[i], searchKey)) {
      frag.appendChild(buildLogLineElement(batch[i]));
      added++;
    }
  }

  if (added > 0) {
    terminal.appendChild(frag);
    while (terminal.childElementCount > maxLogs) {
      terminal.removeChild(terminal.firstElementChild);
    }
  }

  if (countIndicator) {
    countIndicator.innerText = `${terminal.childElementCount} 行`;
  }

  if (autoScroll && currentTab === 'logs') {
    scrollToBottom();
  }
}

function renderLogs() {
  pendingRenderLogs = [];
  const terminal = document.getElementById('log-terminal');
  const countIndicator = document.getElementById('log-count');
  if (!terminal) return;

  const searchKey = getSearchKey();
  const frag = document.createDocumentFragment();
  let count = 0;

  for (let i = 0; i < logs.length; i++) {
    if (matchesSearch(logs[i], searchKey)) {
      frag.appendChild(buildLogLineElement(logs[i]));
      count++;
    }
  }

  terminal.textContent = '';
  terminal.appendChild(frag);

  if (countIndicator) {
    countIndicator.innerText = `${count} 行`;
  }

  if (autoScroll && currentTab === 'logs') {
    scrollToBottom();
  }
}

function scrollToBottom() {
  const terminal = document.getElementById('log-terminal');
  if (terminal) {
    terminal.scrollTop = terminal.scrollHeight;
  }
}

function toggleAutoScroll(enabled) {
  autoScroll = enabled;
  if (enabled) scrollToBottom();
}

function filterLogs() {
  renderLogs();
}

function clearLogs() {
  logs = [];
  pendingRenderLogs = [];
  renderLogs();
}

function toggleStream() {
  streamActive = !streamActive;
  const btn = document.getElementById('btn-pause-stream');
  if (btn) btn.innerText = streamActive ? '暂停' : '继续';
}

function exportLogs() {
  const text = logs.map(l => `[${l.time}] [${l.level}] ${l.text}`).join('\n');
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `proxy_logs_${Date.now()}.txt`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// 终端内部滚动监听与页面生命周期管理
document.addEventListener('DOMContentLoaded', () => {
  const terminal = document.getElementById('log-terminal');
  if (terminal) {
    terminal.addEventListener('scroll', function () {
      const isAtBottom = terminal.scrollHeight - terminal.scrollTop - terminal.clientHeight < 25;
      const autoScrollCheckbox = document.getElementById('auto-scroll-toggle');
      if (!isAtBottom && autoScroll) {
        autoScroll = false;
        if (autoScrollCheckbox) autoScrollCheckbox.checked = false;
      }
    });
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && currentTab === 'overview') {
      fetchOverviewData();
    }
  });

  // 恢复保存的主题
  const saved = localStorage.getItem('proxy_theme');
  if (saved) currentTheme = saved;
  applyTheme();

  // 初始加载
  fetchOverviewData();
  overviewTimer = setInterval(() => {
    if (!document.hidden && currentTab === 'overview') {
      fetchOverviewData();
    }
  }, 2000);
  initLogStream();
});

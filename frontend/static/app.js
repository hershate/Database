/* ========== CVE 漏洞库查询前端 ==========
 * frontend/static/app.js - 连接 CVE-Reports 漏洞库的前端逻辑。
 * 功能：统计可视化 / 搜索（关键词+类型+严重程度+组件+年份+排序）/ 详情 / 导出 /
 *      重建索引 / 删除。接口由 frontend/server.py 提供（/api/cve/*）。
 */

/* ========== API helpers ========== */
const API_BASE = '/api';
async function api(path, opts) {
  const r = await fetch(API_BASE + path, opts);
  if (!r.ok) { let d = ''; try { d = (await r.json()).detail || ''; } catch (e) {} throw new Error(d || ('HTTP ' + r.status)); }
  const txt = await r.text(); return txt ? JSON.parse(txt) : null;
}
function showToast(msg, type) {
  const c = document.getElementById('toast');
  if (!c) { alert(msg); return; }
  const item = document.createElement('div');
  item.className = 'toast-item ' + (type || '');
  item.textContent = msg;
  c.appendChild(item);
  setTimeout(() => { item.style.transition = 'opacity .25s'; item.style.opacity = '0'; setTimeout(() => item.remove(), 250); }, 3500);
}
const _cache = {};
async function cachedApi(path, ttl = 60000) {
  const n = Date.now();
  if (_cache[path] && n - _cache[path].t < ttl) return _cache[path].d;
  const d = await api(path); _cache[path] = { t: n, d: d }; return d;
}
function escapeHtml(s) {
  return (s == null ? '' : String(s)).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function setText(id, v) { var el = document.getElementById(id); if (el) el.textContent = (v == null ? '' : v); }
function val(id) { var el = document.getElementById(id); return el ? el.value : ''; }

/* ========== Modal ========== */
function modalOpen(id) { var el = document.getElementById(id); if (el) el.classList.add('active'); }
function modalClose(id) {
  var el = document.getElementById(id); if (el) el.classList.remove('active');
  // 关闭详情弹窗时清理 URL hash，避免刷新后重复打开
  if (id === 'cveDetailModal' && location.hash) history.replaceState(null, '', location.pathname + location.search);
}
/* ESC 关闭弹窗 */
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') {
    var el = document.getElementById('cveDetailModal');
    if (el && el.classList.contains('active')) modalClose('cveDetailModal');
  }
});

/* ========== CVE 漏洞情报库 ========== */
let _cveDbPage = 1, _cveDbPerPage = 15, _cveDbTotal = 0, _cveGrandTotal = 0;
let _cveDbYearsPopulated = false, _cveDbTypesPopulated = false, _cveDbSoftwarePopulated = false;
let _cveSort = 'year_desc';

function _cveSevClass(s) {
  s = (s || '').toUpperCase();
  return (s === 'CRITICAL' || s === 'HIGH') ? 'critical' : s === 'MEDIUM' ? 'high' : s === 'LOW' ? 'low' : 'queued';
}
function _cveCvssClass(score) {
  var v = parseFloat(score);
  if (isNaN(v)) return 'cvss-none';
  if (v >= 9) return 'cvss-critical';
  if (v >= 7) return 'cvss-high';
  if (v >= 4) return 'cvss-medium';
  return 'cvss-low';
}

/* -- 填充筛选下拉（带守卫，重建/删除后重置标志以刷新） -- */
function _cvePopulateYears(years) {
  if (_cveDbYearsPopulated) return;
  var sel = document.getElementById('cveSearchYear');
  if (!sel || !years) return;
  while (sel.options.length > 1) sel.remove(1);  // 保留首个默认项
  Object.keys(years).sort().reverse().forEach(function (y) {
    var o = document.createElement('option'); o.value = y; o.textContent = y + ' (' + years[y] + ')'; sel.appendChild(o);
  });
  _cveDbYearsPopulated = true;
}
function _cvePopulateTypes(types) {
  if (_cveDbTypesPopulated) return;
  var sel = document.getElementById('cveSearchType');
  if (!sel || !types) return;
  while (sel.options.length > 1) sel.remove(1);
  types.forEach(function (t) {
    var o = document.createElement('option'); o.value = t.name; o.textContent = t.name + ' (' + t.count + ')'; sel.appendChild(o);
  });
  _cveDbTypesPopulated = true;
}
function _cvePopulateSoftware(items) {
  if (_cveDbSoftwarePopulated) return;
  var dl = document.getElementById('cveSoftwareList');
  if (!dl || !items) return;
  dl.innerHTML = '';
  items.forEach(function (it) { var o = document.createElement('option'); o.value = it.name; dl.appendChild(o); });
  _cveDbSoftwarePopulated = true;
}

/* -- 统计条形渲染 -- */
function _cveBarRows(items, max) {
  if (!items || !items.length) return '<div class="bar-empty">暂无数据</div>';
  var top = items.slice(0, max || 10);
  var maxv = top[0].count || 1;
  return top.map(function (it) {
    var pct = Math.max(6, Math.round((it.count / maxv) * 100));
    return '<div class="bar-row" title="' + escapeHtml(it.name) + '：' + it.count + '">' +
      '<span class="bar-label">' + escapeHtml(it.name) + '</span>' +
      '<span class="bar-track"><span class="bar-fill" style="width:' + pct + '%;"></span></span>' +
      '<span class="bar-count">' + it.count + '</span></div>';
  }).join('');
}

async function loadIntel() {
  let cs = { total: 0 };
  try { cs = await api('/cve/stats'); } catch (e) {}
  _cveGrandTotal = cs.total || 0;

  setText('cveDbTotal', cs.total || 0);
  setText('cveDbYearCount', Object.keys(cs.years || {}).length);
  setText('cveDbTypeCount', Object.keys(cs.types || {}).length);
  setText('cveDbCompCount', (cs.software_top || []).length);
  setText('cveDbPath', cs.db_path ? '数据目录：' + cs.db_path : '');

  var cveSev = document.getElementById('cveSevDist');
  if (cveSev && cs.severities) {
    cveSev.innerHTML = Object.keys(cs.severities).map(function (k) {
      return '<span class="status-tag ' + (k === 'CRITICAL' || k === 'HIGH' ? 'critical' : k === 'MEDIUM' ? 'high' : 'low') + '" style="font-size:.62rem;">' + k + ': ' + cs.severities[k] + '</span>';
    }).join(' ');
  }
  var cveNote = document.getElementById('cveDbNote');
  if (cveNote) cveNote.textContent = cs.note || (cs.total + ' 条 CVE · ' + Object.keys(cs.years || {}).length + ' 个年份');

  // 三栏条形：年份分布 / 漏洞类型 Top / 受影响组件 Top
  var yearBars = document.getElementById('cveYearBars');
  if (yearBars && cs.years) {
    var yItems = Object.keys(cs.years).sort().reverse().map(function (y) { return { name: y, count: cs.years[y] }; });
    yearBars.innerHTML = _cveBarRows(yItems, 12);
  }
  var typeBars = document.getElementById('cveTypeBars');
  if (typeBars && cs.types) {
    var tItems = Object.keys(cs.types).map(function (k) { return { name: k, count: cs.types[k] }; }).sort(function (a, b) { return b.count - a.count; });
    typeBars.innerHTML = _cveBarRows(tItems, 10);
  }
  var compBars = document.getElementById('cveCompBars');
  if (compBars) compBars.innerHTML = _cveBarRows(cs.software_top, 10);

  // 填充筛选下拉
  _cvePopulateYears(cs.years);
  if (!_cveDbTypesPopulated) { try { _cvePopulateTypes((await api('/cve/types')).types); } catch (e) {} }
  if (!_cveDbSoftwarePopulated) { try { _cvePopulateSoftware((await api('/cve/software')).software); } catch (e) {} }

  // 首次加载列表（已有数据时不重置当前视图）
  var _cveBody = document.getElementById('cveDbBody');
  if (_cveBody && !_cveBody.children.length) cveDbSearch(1);
}

async function cveDbSearch(page) {
  _cveDbPage = page || 1;
  var psEl = document.getElementById('cveDbPageSize');
  if (psEl) _cveDbPerPage = parseInt(psEl.value, 10) || 15;
  var q = val('cveSearchQ'), sev = val('cveSearchSev'), year = val('cveSearchYear');
  var vtype = val('cveSearchType'), software = val('cveSearchSoftware');
  var qs = '?limit=' + _cveDbPerPage + '&offset=' + ((_cveDbPage - 1) * _cveDbPerPage) + '&sort=' + encodeURIComponent(_cveSort);
  if (q) qs += '&q=' + encodeURIComponent(q);
  if (sev) qs += '&severity=' + encodeURIComponent(sev);
  if (year) qs += '&year=' + encodeURIComponent(year);
  if (vtype) qs += '&vuln_type=' + encodeURIComponent(vtype);
  if (software) qs += '&software=' + encodeURIComponent(software);
  var body = document.getElementById('cveDbBody');
  if (body) body.innerHTML = '<tr><td colspan="8" style="color:var(--text-muted);text-align:center;padding:14px;">加载中…</td></tr>';
  var note = document.getElementById('cveListNote');
  var d; try { d = await api('/cve/search' + qs); } catch (e) { if (body) body.innerHTML = '<tr><td colspan="8" style="color:var(--accent-red);text-align:center;padding:14px;">✗ ' + escapeHtml(e.message) + '</td></tr>'; return; }
  _cveDbTotal = d.total || 0;
  var rows = (d.results || []).map(function (r) {
    var vt = (r.vuln_type || []).slice(0, 2).map(function (t) { return '<span class="status-tag queued" style="font-size:.58rem;">' + escapeHtml(t) + '</span>'; }).join(' ');
    var comp = r.affected_component || '-';
    var compShow = escapeHtml(comp.length > 42 ? comp.slice(0, 42) + '…' : comp);
    var summ = r.summary || '-';
    var summShow = escapeHtml(summ.length > 80 ? summ.slice(0, 80) + '…' : summ);
    var cvss = r.cvss_score;
    return '<tr style="cursor:pointer;" onclick="cveDetail(\'' + escapeHtml(r.cve_id) + '\')">' +
      '<td style="font-family:var(--font-code);font-size:var(--fs-small);color:var(--accent-blue);">' + escapeHtml(r.cve_id) + '</td>' +
      '<td><span class="status-tag ' + _cveSevClass(r.severity) + '" style="font-size:.58rem;">' + escapeHtml(r.severity || '-') + '</span></td>' +
      '<td>' + escapeHtml(r.year || '-') + '</td>' +
      '<td><span class="cvss ' + _cveCvssClass(cvss) + '">' + (cvss == null ? '-' : escapeHtml(cvss)) + '</span></td>' +
      '<td style="max-width:160px;">' + (vt || '<span style="color:var(--text-muted);">-</span>') + '</td>' +
      '<td style="max-width:180px;font-size:.72rem;" title="' + escapeHtml(r.affected_component || '') + '">' + compShow + '</td>' +
      '<td style="max-width:260px;font-size:.72rem;color:var(--text-secondary);" title="' + escapeHtml(r.summary || '') + '">' + summShow + '</td>' +
      '<td><button class="btn btn-sm cve-detail-btn" data-id="' + escapeHtml(r.cve_id) + '">详情</button></td></tr>';
  }).join('');
  if (body) body.innerHTML = rows || '<tr><td colspan="8" style="color:var(--text-muted);text-align:center;padding:14px;">无匹配 CVE</td></tr>';
  document.querySelectorAll('.cve-detail-btn').forEach(function (b) { b.onclick = function (ev) { ev.stopPropagation(); cveDetail(this.dataset.id); }; });
  if (note) note.textContent = _cveGrandTotal ? ('共 ' + _cveGrandTotal + ' 条 · 筛选后 ' + _cveDbTotal + ' 条 · 第 ' + _cveDbPage + '/' + Math.max(1, Math.ceil(_cveDbTotal / _cveDbPerPage)) + ' 页') : ('共 ' + _cveDbTotal + ' 条');
  setText('cveDbPageInfo', '第 ' + _cveDbPage + ' / ' + Math.max(1, Math.ceil(_cveDbTotal / _cveDbPerPage)) + ' 页');
  var prev = document.getElementById('cveDbPrev'), next = document.getElementById('cveDbNext');
  if (prev) prev.disabled = _cveDbPage <= 1;
  if (next) next.disabled = _cveDbPage * _cveDbPerPage >= _cveDbTotal;
  _cveUpdateSortIndicators();
}

function cveDbPage(delta) { cveDbSearch(_cveDbPage + delta); }

function cveClearFilters() {
  ['cveSearchQ', 'cveSearchSev', 'cveSearchYear', 'cveSearchType', 'cveSearchSoftware'].forEach(function (id) {
    var el = document.getElementById(id); if (el) el.value = '';
  });
  _cveSort = 'year_desc';
  cveDbSearch(1);
}

/* -- 列排序：点击表头切换，同列再次点击反转升降序 -- */
function cveToggleSort(sort) {
  if (_cveSort === sort) {
    var base = sort.replace(/_(asc|desc)$/, '');
    _cveSort = base + (sort.endsWith('_desc') ? '_asc' : '_desc');
  } else {
    _cveSort = sort;
  }
  cveDbSearch(1);
}
function _cveUpdateSortIndicators() {
  document.querySelectorAll('th.sortable').forEach(function (th) {
    th.classList.remove('sort-asc', 'sort-desc');
    var s = th.getAttribute('data-sort');
    if (!s) return;
    var base = s.replace(/_(asc|desc)$/, '');
    if (_cveSort === base + '_desc') th.classList.add('sort-desc');
    else if (_cveSort === base + '_asc') th.classList.add('sort-asc');
  });
}

/* -- 漏洞库维护：重建索引 / 导出 / 删除 -- */
function _cveResetFilterCaches() {
  _cveDbYearsPopulated = false; _cveDbTypesPopulated = false; _cveDbSoftwarePopulated = false;
  try { delete _cache['/cve/stats']; } catch (e) {}
}
async function cveRebuild() {
  if (!confirm('确定从文件系统重建索引？将遍历所有 metadata.json 重写 cve-index.json。')) return;
  try {
    var r = await api('/cve/rebuild', { method: 'POST' });
    showToast('索引已重建：' + r.total + ' 条', 'success');
    _cveResetFilterCaches();
    cveDbSearch(_cveDbPage); loadIntel();
  } catch (e) { showToast('✗ 重建失败: ' + e.message, 'error'); }
}
function cveExport() { window.open('/api/cve/export', '_blank'); }
async function cveDownloadReport() {
  var id = _cveCurrentId(); if (!id) return;
  try {
    var d = await api('/cve/' + id);
    if (!d.report) { showToast('该条目无 report.md', 'warn'); return; }
    var blob = new Blob([d.report], { type: 'text/markdown;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = id + '.md';
    document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
    showToast('已下载 ' + id + '.md', 'success');
  } catch (e) { showToast('✗ 下载失败: ' + e.message, 'error'); }
}
async function cveDeleteCurrent() {
  var id = _cveCurrentId(); if (!id) return;
  if (!confirm('确定删除 ' + id + '？将删除其目录并从索引中移除。')) return;
  try {
    var r = await api('/cve/' + id, { method: 'DELETE' });
    showToast('已删除 ' + id + '（剩余 ' + r.remaining + ' 条）', 'success');
    modalClose('cveDetailModal');
    _cveResetFilterCaches();
    cveDbSearch(_cveDbPage); loadIntel();
  } catch (e) { showToast('✗ 删除失败: ' + e.message, 'error'); }
}
function _cveCurrentId() {
  var t = document.getElementById('cveDetailTitle'); if (!t) return '';
  var m = /^(CVE-\d{4}-\d{4,})/.exec(t.textContent); return m ? m[1] : '';
}
async function cveCopyId() {
  var id = _cveCurrentId(); if (!id) return;
  try { await navigator.clipboard.writeText(id); showToast('已复制 ' + id, 'success'); }
  catch (e) { showToast('复制失败，请手动选择', 'error'); }
}

async function cveDetail(cveId) {
  var title = document.getElementById('cveDetailTitle');
  var meta = document.getElementById('cveDetailMeta');
  var rep = document.getElementById('cveDetailReport');
  if (title) title.textContent = cveId + ' 详情';
  var copyBtn = document.getElementById('cveCopyIdBtn'); if (copyBtn) copyBtn.style.display = '';
  if (meta) meta.innerHTML = '<span style="color:var(--text-muted);">加载中…</span>';
  if (rep) rep.innerHTML = '';
  modalOpen('cveDetailModal');
  // URL hash 深链：#CVE-YYYY-NNNN 可分享、刷新保持
  if (location.hash !== '#' + cveId) history.replaceState(null, '', '#' + cveId);
  var d; try { d = await api('/cve/' + encodeURIComponent(cveId)); } catch (e) { if (meta) meta.innerHTML = '<span style="color:var(--accent-red);">✗ ' + escapeHtml(e.message) + '</span>'; return; }
  if (meta) meta.innerHTML = _cveDetailMetaHtml(d);
  if (rep) rep.innerHTML = d.report ? renderMarkdown(d.report) : '<span style="color:var(--text-muted);">该条目暂无 report.md（仅索引元数据）</span>';
}

function _cveDetailMetaHtml(d) {
  var rows = [
    ['CVE ID', escapeHtml(d.cve_id || '-')],
    ['严重程度', '<span class="status-tag ' + _cveSevClass(d.severity) + '" style="font-size:.62rem;">' + escapeHtml(d.severity || 'UNKNOWN') + '</span>'],
    ['CVSS', '<span class="cvss ' + _cveCvssClass(d.cvss_score) + '">' + (d.cvss_score == null ? '-' : escapeHtml(d.cvss_score)) + '</span>'],
    ['年份', escapeHtml(d.year || '-')],
    ['CWE', (d.cwe || []).map(function (c) { return '<span class="status-tag queued" style="font-size:.6rem;">' + escapeHtml(c) + '</span>'; }).join(' ') || '-'],
    ['漏洞类型', (d.vuln_type || []).map(function (t) { return '<span class="status-tag queued" style="font-size:.6rem;">' + escapeHtml(t) + '</span>'; }).join(' ') || '-'],
    ['受影响组件', escapeHtml(d.affected_component || '-')],
    ['PoC', d.has_poc ? '<span class="status-tag high" style="font-size:.6rem;">有 PoC</span>' : '<span class="status-tag low" style="font-size:.6rem;">无 PoC</span>'],
    ['缓解', d.has_mitigation ? '<span class="status-tag completed" style="font-size:.6rem;">有缓解</span>' : '<span class="status-tag low" style="font-size:.6rem;">无</span>'],
    ['来源数', escapeHtml(d.source_count || 0)],
    ['收集日期', escapeHtml(d.collection_date || '-')],
    ['标签', (d.tags || []).map(function (t) { return '<span class="status-tag queued" style="font-size:.58rem;">' + escapeHtml(t) + '</span>'; }).join(' ') || '-'],
    ['报告路径', d.report_path ? '<code style="font-family:var(--font-code);font-size:.72rem;word-break:break-all;">' + escapeHtml(d.report_path) + '</code>' : '-'],
  ];
  return '<div class="detail-grid">' + rows.map(function (r) {
    return '<div class="detail-row"><span class="detail-key">' + r[0] + '</span><span class="detail-val">' + r[1] + '</span></div>';
  }).join('') + '</div><div style="margin:10px 0 4px;font-size:var(--fs-small);color:var(--text-muted);">摘要</div><div style="font-size:var(--fs-small);color:var(--text-secondary);line-height:1.6;">' + escapeHtml(d.summary || '-') + '</div>';
}

/* -- 极简 Markdown 渲染（标题/表格/列表/代码块/加粗/行内代码/链接） -- */
function renderMarkdown(md) {
  if (!md) return '';
  var esc = function (s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); };
  var inline = function (s) {
    s = esc(s);
    s = s.replace(/`([^`]+)`/g, '<code style="font-family:var(--font-code);background:var(--bg-elevated);padding:1px 5px;border-radius:4px;font-size:.85em;">$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-primary);">$1</strong>');
    s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" style="color:var(--accent-blue);">$1</a>');
    return s;
  };
  var lines = md.replace(/\r\n/g, '\n').split('\n');
  var html = '', i = 0;
  while (i < lines.length) {
    var ln = lines[i];
    // 代码块
    if (/^```/.test(ln)) {
      var code = []; i++;
      while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i++; }
      i++;
      html += '<pre style="background:var(--bg-elevated);border:1px solid var(--border);border-radius:6px;padding:10px;overflow:auto;font-family:var(--font-code);font-size:.78rem;color:var(--text-primary);">' + esc(code.join('\n')) + '</pre>';
      continue;
    }
    // 表格
    if (/\|/.test(ln) && i + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[i + 1])) {
      var hdr = ln.split('|').map(function (x) { return x.trim(); }).filter(function (x, i2, a) { return !(i2 === 0 && x === '') && !(i2 === a.length - 1 && x === ''); });
      i += 2; var rowsT = [];
      while (i < lines.length && /\|/.test(lines[i])) { rowsT.push(lines[i]); i++; }
      var t = '<table style="width:100%;border-collapse:collapse;font-size:.8rem;margin:8px 0;"><thead><tr>';
      hdr.forEach(function (h) { t += '<th style="border:1px solid var(--border);padding:5px 8px;text-align:left;background:var(--bg-elevated);">' + inline(h) + '</th>'; });
      t += '</tr></thead><tbody>';
      rowsT.forEach(function (r) {
        var cells = r.split('|').map(function (x) { return x.trim(); }).filter(function (x, i2, a) { return !(i2 === 0 && x === '') && !(i2 === a.length - 1 && x === ''); });
        t += '<tr>'; cells.forEach(function (c) { t += '<td style="border:1px solid var(--border);padding:5px 8px;">' + inline(c) + '</td>'; }); t += '</tr>';
      });
      html += t + '</tbody></table>';
      continue;
    }
    // 标题
    var hm = /^(#{1,6})\s+(.*)$/.exec(ln);
    if (hm) { var lv = hm[1].length; var sizes = ['1.1rem', '1.05rem', '.98rem', '.9rem', '.85rem', '.8rem']; html += '<h' + lv + ' style="margin:12px 0 6px;font-family:var(--font-display);font-weight:600;color:var(--text-primary);font-size:' + sizes[lv - 1] + ';">' + inline(hm[2]) + '</h' + lv + '>'; i++; continue; }
    // 水平线
    if (/^\s*([-*_])\1{2,}\s*$/.test(ln)) { html += '<hr style="border:none;border-top:1px solid var(--border);margin:12px 0;" />'; i++; continue; }
    // 无序列表
    if (/^\s*[-*+]\s+/.test(ln)) {
      var items = []; while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) { items.push(lines[i].replace(/^\s*[-*+]\s+/, '')); i++; }
      html += '<ul style="margin:6px 0 6px 18px;padding:0;">' + items.map(function (x) { return '<li style="margin:2px 0;">' + inline(x) + '</li>'; }).join('') + '</ul>';
      continue;
    }
    // 有序列表
    if (/^\s*\d+\.\s+/.test(ln)) {
      var itemsO = []; while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) { itemsO.push(lines[i].replace(/^\s*\d+\.\s+/, '')); i++; }
      html += '<ol style="margin:6px 0 6px 20px;padding:0;">' + itemsO.map(function (x) { return '<li style="margin:2px 0;">' + inline(x) + '</li>'; }).join('') + '</ol>';
      continue;
    }
    // 空行
    if (/^\s*$/.test(ln)) { i++; continue; }
    // 段落（合并连续非空行）
    var para = ln; i++;
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !/^```/.test(lines[i]) && !/^(#{1,6})\s/.test(lines[i]) && !/\|/.test(lines[i]) && !/^\s*[-*+]\s+/.test(lines[i]) && !/^\s*\d+\.\s+/.test(lines[i])) { para += ' ' + lines[i]; i++; }
    html += '<p style="margin:6px 0;">' + inline(para) + '</p>';
  }
  return html;
}

/* ========== 启动 ========== */
document.addEventListener('DOMContentLoaded', function () {
  loadIntel();
  // URL hash 深链：#CVE-YYYY-NNNN 直接打开详情
  var m = /^#(CVE-\d{4}-\d{4,})$/i.exec(location.hash);
  if (m) cveDetail(m[1].toUpperCase());
  // "/" 聚焦搜索框（输入控件聚焦时不拦截）
  document.addEventListener('keydown', function (e) {
    if (e.key === '/') {
      var tag = document.activeElement && document.activeElement.tagName;
      if (tag !== 'INPUT' && tag !== 'SELECT' && tag !== 'TEXTAREA') {
        var q = document.getElementById('cveSearchQ');
        if (q) { e.preventDefault(); q.focus(); }
      }
    }
  });
});

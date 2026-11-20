/* Aletto Attribution UI. Self-contained: reads data.enc (AES-GCM, PBKDF2-SHA256), decrypts in the browser, renders.
   No network calls beyond fetching data.enc from the same origin. No inline scripts (MV3-compatible). */
'use strict';
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
let ENC = null, P = null;
const DATA_URL = (window.ALETTO_DATA_URL || 'data.enc');

// ---------------- unlock ----------------
async function derive(pass, salt, iter) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256'}, k, {name: 'AES-GCM', length: 256}, true, ['decrypt']);
}
async function openKey(key) {
  const pt = await crypto.subtle.decrypt({name: 'AES-GCM', iv: b64(ENC.iv), additionalData: new TextEncoder().encode(ENC.aad)}, key, b64(ENC.ct));
  const ds = new Blob([pt]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(ds).text());
}
async function boot() {
  ENC = await (await fetch(DATA_URL, {cache: 'no-store'})).json();
  const sk = sessionStorage.getItem('axk');
  if (sk) { try { const key = await crypto.subtle.importKey('raw', b64(sk), 'AES-GCM', true, ['decrypt']); P = await openKey(key); start(); return; } catch (e) { sessionStorage.removeItem('axk'); } }
}
$('#gf').addEventListener('submit', async e => {
  e.preventDefault(); $('#err').textContent = ''; $('#ub').textContent = 'Unlocking…';
  try {
    if (!ENC) await boot();
    const key = await derive($('#pw').value, b64(ENC.salt), ENC.iter); P = await openKey(key);
    if ($('#rem').checked) { const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key)); sessionStorage.setItem('axk', btoa(String.fromCharCode(...raw))); }
    $('#pw').value = ''; start();
  } catch (err) { $('#err').textContent = 'Wrong passphrase.'; $('#ub').textContent = 'Unlock'; }
});
boot().catch(() => {});

// ---------------- formatting ----------------
const fmt$ = v => v == null || !isFinite(v) ? '–' : (Math.abs(v) < 0.005 ? '$0' : '$' + (Math.abs(v) >= 100 ? Math.round(v).toLocaleString('en-US') : v.toFixed(2)));
const fmtN = v => v == null || !isFinite(v) ? '–' : Math.round(v).toLocaleString('en-US');
const pct = v => v == null || !isFinite(v) ? '–' : (v * 100).toFixed(v < 0.1 && v > 0 ? 1 : 0) + '%';
const dv = (a, b) => b ? a / b : null;
const MAD = 'Europe/Madrid', NY = 'America/New_York';
function tfmt(iso, both = true) {
  if (!iso) return '';
  const d = new Date(iso);
  const m = d.toLocaleString('en-GB', {timeZone: MAD, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'});
  if (!both) return m;
  const e = d.toLocaleString('en-US', {timeZone: NY, hour: 'numeric', minute: '2-digit'});
  return `${m} Madrid · ${e} ET`;
}
function dfmt(iso) { return iso ? new Date(iso).toLocaleDateString('en-GB', {timeZone: MAD, day: 'numeric', month: 'short'}) : ''; }
const dayLabel = i => { const [y, m, d] = P.days[i].split('-').map(Number); return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString('en-GB', {timeZone: 'UTC', day: 'numeric', month: 'short'}); };

// ---------------- state ----------------
const S = {view: 'ads', r: '14', today: false, plat: 'paid', model: 'rule', basis: 'cohort', sort: 'spend', dir: -1, open: new Set(), full: false, hz: true, adq: '',
  lq: '', lscope: 'created', lms: '', lch: '', lsort: 'ct', ldir: -1, llim: 150, wf: 'all', wopen: new Set()};
const CC = {'LinkedIn Ads': '#60a5fa', 'Meta Ads': '#a78bfa', 'Google Ads': '#fbbf24', 'Organic social': '#34d399', 'Organic search': '#2dd4bf', 'AI assistants': '#f472b6', 'Email & SMS': '#fb923c', 'Referral': '#94a3b8', 'Direct / unknown': '#4b5563'};
const PAID = ['LinkedIn Ads', 'Meta Ads', 'Google Ads'];
const DEF = {}; // key -> [label, text]

function rng() {
  const n = P.days.length, last = S.today ? n - 1 : n - 2;
  if (S.r === 'c') {
    let a = P.days.indexOf($('#d0').value), b = P.days.indexOf($('#d1').value);
    if (a < 0) a = 0; if (b < 0) b = last; if (a > b) [a, b] = [b, a]; return [a, b];
  }
  const k = +S.r; return [Math.max(0, last - k + 1), last];
}
function platOk(ch) { return S.plat === 'all' ? true : S.plat === 'paid' ? PAID.includes(ch) : S.plat === 'li' ? ch === 'LinkedIn Ads' : ch === 'Meta Ads'; }

// ---------------- aggregation (mirrors agg.py) ----------------
const CNT = ['leads', 'ql', 'qu', 'sb', 'ss', 'sn', 'qs', 'cb', 'ch', 'cn', 'sd', 'ab', 'ah', 'w'];
const zero = () => ({spend: 0, cs: 0, impr: 0, clicks: 0, pl: 0, rev: 0, cash: 0, xcash: 0, ...Object.fromEntries(CNT.map(k => [k, 0])), xn: Object.fromEntries(CNT.map(k => [k, 0])), ids: Object.fromEntries(CNT.map(k => [k, []]))});
function hits(L, a, b) {
  const inr = d => d != null && d >= a && d <= b, M = L.m, coh = S.basis === 'cohort';
  const created = inr(L.cd);
  if (coh && !created) return null;
  const has = arr => coh ? arr.length > 0 : arr.some(inr);
  const h = {leads: created, ql: created && L.q === 1, qu: created && L.q == null, sb: has(M.sb), ss: has(M.ss), sn: has(M.sn) && !has(M.ss), qs: has(M.qs), cb: has(M.cb), ch: has(M.ch), cn: has(M.cn) && !has(M.ch),
    sd: has(M.sd), ab: has(M.ab), ah: has(M.ah), w: M.w != null && (coh || inr(M.w))};
  h.rev = h.w ? M.rev : 0; h.cash = M.cash.reduce((s, [d, v]) => s + (coh || inr(d) ? v : 0), 0);
  return h;
}
function add(o, h, li, nr) {
  for (const k of CNT) if (h[k]) { o[k]++; o.ids[k].push(li); if (nr) o.xn[k]++; }
  o.rev += h.rev; o.cash += h.cash; if (nr) o.xcash += h.cash;
}
function pathsOf(i) { const k = P.ents[i].k, out = [k[0], k[0] + '›' + k[1], k[0] + '›' + k[1] + '›' + k[2]]; if (k[3]) out.push(out[2] + '›' + k[3]); return out; }
let PATHS = null;
function aggregate(a, b, platFilter = true) {
  if (!PATHS) PATHS = P.ents.map((e, i) => pathsOf(i));
  const N = {}, T = zero(); const g = p => N[p] || (N[p] = zero());
  for (const [d, i, s, im, cl, pl] of P.sp) {
    if (d < a || d > b) continue; const ch = P.ents[i].k[0]; if (platFilter && !platOk(ch)) continue;
    const c = P.ents[i].nt ? 0 : s;  // IG post boosts: no lead tracking -> not in cost-per-stage
    for (const p of PATHS[i]) { const o = g(p); o.spend += s; o.cs += c; o.impr += im; o.clicks += cl; o.pl += pl || 0; }
    T.spend += s; T.cs += c; T.impr += im; T.clicks += cl; T.pl += pl || 0;
  }
  P.leads.forEach((L, li) => {
    const i = L.a[S.model], ch = P.ents[i].k[0]; if (platFilter && !platOk(ch)) return;
    const h = hits(L, a, b); if (!h) return;
    if (!CNT.some(k => h[k]) && !h.cash) return;
    const nr = !!P.ents[i].nr;  // old Meta account: spend not readable -> leads not in cost-per-stage
    for (const p of PATHS[i]) add(g(p), h, li, nr);
    add(T, h, li, nr);
  });
  return {N, T};
}
// Cost per stage = spend WITH lead tracking (cs) ÷ count of leads whose spend is readable (count − xn).
const cp = (o, k) => { const n = o[k] - (o.xn ? o.xn[k] : 0); return o.cs && n ? o.cs / n : null; };
function costState(o, k) { // why a cost cell is blank: 'na' spend not readable, 'nt' no lead tracking, 'none' none of that step yet
  const n = o[k] - (o.xn ? o.xn[k] : 0);
  if (!o.cs) return o.spend ? 'nt' : (o[k] && o.xn && o.xn[k] === o[k] ? 'na' : '');
  return n ? '' : 'none';
}
function derived(o) {
  const s = o.spend;
  return Object.assign(o, {ctr: dv(o.clicks, o.impr), cpm: o.impr ? s / o.impr * 1000 : null, cpl: cp(o, 'leads'), cpql: cp(o, 'ql'), cpsb: cp(o, 'sb'),
    cpqs: cp(o, 'qs'), cpcb: cp(o, 'cb'), cpch: cp(o, 'ch'), roas: o.cs ? (o.cash - (o.xcash || 0)) / o.cs : null, qlr: dv(o.ql, o.leads), sdr: dv(o.sd, o.ss),
    showr: dv(o.ss, o.ss + o.sn), hr: dv(o.ch, o.ch + o.cn)});
}

// ---------------- reconciliation ----------------
const SLOTS = [[1, 7, 30], [1, 14, 0], [2, 7, 30], [2, 14, 0], [3, 7, 30], [3, 14, 0], [4, 7, 30], [4, 14, 0], [5, 7, 30], [5, 10, 30], [5, 14, 0]]; // Madrid weekday, h, m
function madridParts(d) { const o = {}; for (const p of new Intl.DateTimeFormat('en-GB', {timeZone: MAD, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', weekday: 'short'}).formatToParts(d)) o[p.type] = p.value; return o; }
function madridToDate(y, m, d, hh, mm) { // Madrid wall time -> Date (two-pass offset)
  let t = Date.UTC(y, m - 1, d, hh, mm);
  for (let k = 0; k < 2; k++) { const p = madridParts(new Date(t)); const w = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute); t += Date.UTC(y, m - 1, d, hh, mm) - w; }
  return new Date(t);
}
function lastSlot(now = new Date()) { // most recent scheduled refresh that should have finished (45 min grace)
  for (let back = 0; back < 9; back++) {
    const p = madridParts(new Date(now - back * 864e5)), wd = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(p.weekday);
    const ss = SLOTS.filter(x => x[0] === wd).map(x => madridToDate(+p.year, +p.month, +p.day, x[1], x[2])).filter(t => +t + 45 * 6e4 <= +now).sort((x, y) => y - x);
    if (ss.length) return ss[0];
  }
  return null;
}
function recon(a, b) {
  const R = P.recon, sum = arr => (arr || []).slice(a, b + 1).reduce((s, x) => s + x, 0);
  const A = aggregate(a, b, false).T;
  const raw = sum(R.raw), xo = sum(R.x_noopt), xt = sum(R.x_test), xd = sum(R.x_dup), exp = raw - xo - xt - xd;
  const li = sum(R.li), lic = sum(R.li_campaign), mh = sum(R.meta_heat), ig = sum(R.meta_ig);
  const checks = [
    {ok: A.leads === exp, t: `${fmtN(raw)} new GHL contacts − ${fmtN(xo)} outbound/WhatsApp, no opt-in − ${fmtN(xt)} test/spam${xd ? ` − ${fmtN(xd)} duplicates` : ''} = ${fmtN(exp)} leads (all sources); portal ${fmtN(A.leads)}`, why: 'Raw count = every contact GHL created in the range (ET), no filters. Click to see every excluded contact and why.', act: 'excl'},
    {ok: Math.abs(A.spend - (li + mh + ig)) < 0.05, t: `Spend ${fmt$(A.spend)} = LinkedIn ${fmt$(li)} + Meta ${fmt$(mh)} + IG boosts ${fmt$(ig)}`, why: 'Portal spend equals the sum of the ad account pulls. IG boosts have no lead tracking, so they are left out of cost per lead / Strat / Scope.'},
    {ok: Math.abs(li - lic) < 0.05, t: `LinkedIn ad-level = campaign-level (${fmt$(lic)})`, why: 'Two independent LinkedIn reports agree.'},
    {ok: !!R.pull_reaches_start, t: 'GHL contact pull covers the full window', why: `Oldest contact pulled: ${R.oldest_contact}`},
  ];
  const heat0 = P.days.indexOf('2026-11-19'), oldLeads = A.xn.leads + A.xn.sb + A.xn.cb;
  if ((heat0 < 0 || a < heat0) && (oldLeads || S.plat !== 'li')) checks.push({ok: false, warn: 'amber', t: `Old Meta account spend not included (before Nov 19)${A.xn.leads ? `: ${fmtN(A.xn.leads)} Meta leads have no readable spend, left out of costs` : ''}`, why: 'act_1624265171591278 is not readable (no ads_read). Its leads are counted; its spend is missing, so they are left out of every cost per stage.'});
  const g = new Date(P.meta.generated), ls = lastSlot(), age = (Date.now() - g) / 36e5;
  const missed = ls && +g < +ls - 10 * 6e4;
  checks.push({ok: !missed, warn: missed ? 'red' : true, t: missed ? `Stale: last refresh ${Math.round(age)} h ago, missed the ${tfmt(ls.toISOString(), false)} run` : `Data ${age < 1 ? 'under 1 hour' : Math.round(age) + ' h'} old`, why: 'Scheduled refresh: weekdays 07:30 and 14:00 Madrid, plus Fri 10:30. Red after one missed run.'});
  return checks;
}
function reconStrip(a, b) {
  const C = recon(a, b), bad = C.filter(c => !c.ok && !c.warn), amb = C.filter(c => !c.ok && c.warn);
  const head = bad.length ? '<b>Check failed: numbers below may be wrong. Do not optimise on them until the next refresh passes.</b>' : `<b>Reconciled${amb.length ? ', with gaps' : ''}</b>`;
  const h = `<div class="rc ${bad.length ? 'fail' : ''}">${head}
   ${C.map(c => `<span class="${c.ok ? 'ok' : (c.warn === 'amber' ? 'w' : 'x')}${c.act ? ' act' : ''}" ${c.act ? `data-act="${c.act}" role="button" tabindex="0"` : ''} title="${esc(c.why)}">${c.ok ? '✓' : (c.warn === 'amber' ? '!' : '✗')} ${esc(c.t)}${c.act ? ' <u>see excluded</u>' : ''}</span>`).join('')}</div>`;
  return {h, bad: bad.length > 0};
}
function wireRecon(el) { el.querySelectorAll('[data-act="excl"]').forEach(x => x.addEventListener('click', () => exclList())); }
function exclList() {
  const [a, b] = rng(), X = (P.excl || []).filter(x => x[1] >= a && x[1] <= b);
  const by = {}; X.forEach(x => (by[x[2]] = by[x[2]] || []).push(x));
  drawer('Contacts not counted as leads', `${X.length} new GHL contacts in ${esc(rangeText())} · each with the reason`,
    Object.entries(by).sort((p, q) => q[1].length - p[1].length).map(([why, xs]) => `<h5>${esc(why)} · ${xs.length}</h5><ul class="ll">${xs.map(x => `<li><div>${esc(x[3] || x[4] || '(no name)')}<small>${esc(x[5] || x[4] || '')}${x[6] ? ' · tags: ' + esc(x[6]) : ''}</small></div><div class="num"><a href="https://app.gohighlevel.com/v2/location/hRwcvshOuGeKsIDdUFL5/contacts/detail/${esc(x[0])}" target="_blank" rel="noopener noreferrer">GHL ↗</a> ${dayLabel(x[1])}</div></li>`).join('')}</ul>`).join('') || '<div class="empty">None in this range.</div>');
}

// ---------------- columns ----------------
// [key, label, kind, full-only, funnel-prev]
const COLS = [
  ['spend', 'Spend', '$'], ['impr', 'Impressions', 'n', 1], ['clicks', 'Clicks', 'n', 1], ['ctr', 'Click-through rate', '%', 1], ['cpm', 'Cost per 1,000 impressions', '$', 1], ['pl', 'Platform-reported leads', 'n', 1],
  ['leads', 'Leads', 'c'], ['cpl', 'Cost per lead', '$'], ['ql', 'Quality leads', 'c', 0, 'leads'], ['qu', 'Revenue unknown', 'c'], ['cpql', 'Cost per quality lead', '$', 1],
  ['sb', 'Strats booked', 'c', 0, 'leads'], ['cpsb', 'Cost per Strat', '$', 1], ['ss', 'Strats showed', 'c', 0, 'sb'], ['sn', 'Strat no-shows', 'c'], ['qs', 'Qualified Strats', 'c', 0, 'ss'], ['cpqs', 'Cost per qualified Strat', '$'],
  ['cb', 'Scopes booked', 'c', 0, 'qs'], ['cpcb', 'Cost per Scope booked', '$'], ['sdr', 'Same-day Scope %', '%'], ['ch', 'Scopes held', 'c', 0, 'cb'], ['cn', 'Scope no-shows', 'c', 1], ['cpch', 'Cost per Scope held', '$'],
  ['ah', 'Alignments held', 'c', 0, 'ch'], ['w', 'Won', 'c', 0, 'ah'], ['rev', 'Revenue', '$', 1], ['cash', 'Cash collected', '$'], ['roas', 'Cash ÷ spend', 'x', 1]];
const DEFKEY = {sdr: 'sd', ah: 'ah', sn: 'sn', cn: 'cn', pl: 'pl', qu: 'qu'};
const NONE = {none: ['none yet', 'Money spent and none of this step yet'], na: ['spend not readable', 'Old Meta account: spend cannot be read, so no cost'], nt: ['no lead tracking', 'IG post boosts: spend with no lead tracking, so no cost per step']};
function cell(o, c) {
  const [k, , kind, , prev] = c, v = o[k];
  if (kind === 'c') {
    const sub = prev && o[prev] ? `<small>${pct(v / o[prev])}</small>` : '';
    return v ? `<td class="c" data-m="${k}">${fmtN(v)}${sub}</td>` : `<td><span class="z">0</span></td>`;
  }
  if (kind === '$') {
    let cls = '';
    if (k === 'cpcb' && v != null) cls = v <= P.meta.target_scope ? 'good' : 'bad';
    const base = {cpl: 'leads', cpql: 'ql', cpsb: 'sb', cpqs: 'qs', cpcb: 'cb', cpch: 'ch'}[k];
    if (base && v == null) { const st = costState(o, base); if (st) return `<td><span class="z nb" title="${NONE[st][1]}">${NONE[st][0]}</span></td>`; }
    return `<td class="${cls}">${v == null ? '<span class="z">–</span>' : fmt$(v)}</td>`;
  }
  if (kind === '%') return `<td>${v == null ? '<span class="z">–</span>' : pct(v)}</td>`;
  if (kind === 'x') return `<td>${v == null ? '<span class="z">–</span>' : v.toFixed(2) + '×'}</td>`;
  return `<td>${v ? fmtN(v) : '<span class="z">0</span>'}</td>`;
}
function th(c) {
  const [k, lab] = c, d = DEF[DEFKEY[k] || k];
  return `<th data-k="${k}" class="${S.sort === k ? 'sorted' : ''}" title="${esc(d ? d[1] : lab)}">${esc(lab)}${S.sort === k ? (S.dir < 0 ? ' ↓' : ' ↑') : ''}<span class="i" data-def="${DEFKEY[k] || k}">i</span></th>`;
}

// ---------------- ADS view ----------------
function tree(N) {
  const kids = {};
  for (const p of Object.keys(N)) { const parts = p.split('›'); const par = parts.slice(0, -1).join('›'); (kids[par] = kids[par] || []).push(p); }
  return kids;
}
function sortVal(o) {
  const v = o[S.sort];
  if (S.sort.startsWith('cp')) { // cost: lower is better; spend with zero of the thing = worst; no spend = bottom
    if (!o.spend) return S.dir < 0 ? -Infinity : Infinity;
    return v == null ? (S.dir < 0 ? -1e12 : 1e12) : v;
  }
  return v == null ? -Infinity : v;
}
function entOf(path) { // ad set / ad entity record for status + budget + ids
  const parts = path.split('›'); const k = [parts[0], parts[1] || '', parts[2] || '', parts[3] || ''];
  return P.ents.find(e => e.k[0] === k[0] && e.k[1] === k[1] && e.k[2] === k[2] && e.k[3] === k[3]);
}
function nmH(nm) { const l = (P.labels || {})[nm]; return l ? `${esc(l)} <span class="code">${esc(nm)}</span>` : esc(nm); }
const nmT = nm => (P.labels || {})[nm] || nm;
function renderAds() {
  const [a, b] = rng(); const {N, T} = aggregate(a, b); derived(T); Object.values(N).forEach(derived);
  const rc = reconStrip(a, b);
  $('#arc').innerHTML = rc.h; wireRecon($('#arc'));
  const k = (l, v, s, cls = '', def = '') => `<div class="kpi"><div class="l">${l}${def ? `<span class="i" data-def="${def}">i</span>` : ''}</div><div class="v ${cls}">${rc.bad ? '<span class="z">check</span>' : v}</div><div class="s">${s}</div></div>`;
  const cst = (v, base) => v != null ? fmt$(v) : (NONE[costState(T, base)] || ['–'])[0];
  const xl = T.xn.leads ? ` · ${fmtN(T.xn.leads)} Meta leads with no readable spend left out` : '';
  $('#kpis').innerHTML = k('Spend', fmt$(T.spend), `${fmtN(T.impr)} impressions · ${pct(T.ctr)} click-through`, '', 'spend') + k('Leads', fmtN(T.leads), `${cst(T.cpl, 'leads')} per lead${xl}${S.plat !== 'all' ? ` · ${fmtN(aggregate(a, b, false).T.leads)} all sources` : ''}`, '', 'leads')
    + k('Quality leads', fmtN(T.ql) + `<small>${pct(T.qlr)}</small>`, `${cst(T.cpql, 'ql')} each · ${fmtN(T.qu)} revenue unknown`, '', 'ql')
    + k('Strats booked', fmtN(T.sb), `${fmtN(T.ss)} showed · show rate ${pct(T.showr)} (excl. cancels)`, '', 'sb') + k('Qualified Strats', fmtN(T.qs), `${cst(T.cpqs, 'qs')} each`, '', 'qs')
    + k('Same-day Scope %', pct(T.sdr), `${fmtN(T.sd)} of ${fmtN(T.ss)} Strat shows booked a Scope that day`, '', 'sd')
    + k('Scopes booked', fmtN(T.cb), `${cst(T.cpcb, 'cb')} each · target $${P.meta.target_scope}`, T.cpcb != null ? (T.cpcb <= P.meta.target_scope ? 'good' : 'bad') : '', 'cb')
    + k('Scopes held', fmtN(T.ch), `${cst(T.cpch, 'ch')} each`, '', 'ch') + k('Alignments held', fmtN(T.ah), `${fmtN(T.ab)} booked`, '', 'ah')
    + k('Won', fmtN(T.w), `${fmt$(T.rev)} deal value · ${fmt$(T.cash)} cash`, '', 'w');
  trend(a, b);
  const cols = COLS.filter(c => S.full || !c[3]);
  $('#tbl thead').innerHTML = `<tr><th data-k="name">${innerWidth < 640 ? 'Campaign › ad set › ad' : 'Account › Campaign › Ad set › Ad'}</th>${cols.map(th).join('')}</tr>`;
  const kids = tree(N), q = S.adq.trim().toLowerCase();
  const match = p => !q || p.toLowerCase().includes(q);
  const anyMatch = p => match(p) || (kids[p] || []).some(anyMatch);
  const rows = [];
  const walk = (par, lvl) => {
    const ks = (kids[par] || []).filter(p => { const o = N[p]; if (S.hz && !o.spend && !CNT.some(x => o[x]) && !o.cash) return false; return anyMatch(p); });
    ks.sort((x, y) => {
      if (S.sort === 'name') return x.localeCompare(y) * -S.dir;
      const vx = sortVal(N[x]), vy = sortVal(N[y]);
      return (vx === vy ? 0 : (S.dir < 0 ? (vy > vx ? 1 : -1) : (vx > vy ? 1 : -1))) || x.localeCompare(y);
    });
    for (const p of ks) {
      const o = N[p], parts = p.split('›'), nm = parts[parts.length - 1], has = (kids[p] || []).length > 0;
      const open = S.open.has(p) || (q && lvl < 3 && (kids[p] || []).some(anyMatch));
      const e = lvl >= 2 ? entOf(p) : null, un = parts[1] === 'Unattributed' || parts[1] === 'Old Meta account (spend not readable)';
      let badge = '';
      const ruleN = (o.ids.leads || []).filter(li => P.ents[P.leads[li].a[S.model]].ids.rule).length;
      if (lvl < 2 && ruleN && !open) badge += ` <span class="tag rule" title="Includes leads from the bare lnkd.in link in LinkedIn ad copy (no UTMs), counted as LinkedIn ad leads by Jake's Nov 19 rule. Expand to see them.">${ruleN} attributed by rule</span>`;
      if (e && e.st) badge += ` <span class="pill ${e.st}">${e.st}${e.bud && lvl === 2 ? ' · $' + Math.round(e.bud) + '/day' : ''}</span>`;
      if (e && e.ids && e.ids.rule) badge += ` <span class="tag rule" title="These leads came from the bare lnkd.in link in the LinkedIn ad copy (no UTMs). Counted as LinkedIn ad leads by Jake's Nov 19 rule; the ad set cannot be known.">attributed by rule</span>`;
      if (lvl === 1 && parts[1] === 'Old Meta account (spend not readable)') badge += ' <span class="tag part" title="act_1624265171591278: no read access, so spend is missing and costs cannot be computed">no spend access</span>';
      const ids = e && e.ids ? Object.entries(e.ids).filter(([k]) => k !== 'rule').map(([k, v]) => `${k} ${v}`).join(' · ') : '';
      rows.push(`<tr class="l${lvl} ${has ? 'has' : ''} ${open ? 'open' : ''} ${un ? 'unat' : ''}" data-p="${esc(p)}"><td title="${esc(nm + (ids ? ' · ' + ids : ''))}">${has ? '<span class="car">›</span>' : '<span class="car"></span>'}${lvl === 0 ? `<span class="dot" style="background:${CC[nm] || '#666'}"></span>` : ''}${nmH(nm)}${badge}</td>${cols.map(c => cell(o, c)).join('')}</tr>`);
      if (has && open) walk(p, lvl + 1);
    }
  };
  walk('', 0);
  rows.push(`<tr class="tot"><td>Total (${esc(S.plat === 'all' ? 'all sources' : S.plat === 'paid' ? 'paid' : S.plat === 'li' ? 'LinkedIn' : 'Meta')})</td>${cols.map(c => cell(T, c)).join('')}</tr>`);
  $('#tbl tbody').innerHTML = rows.join('');
  window.__N = N; window.__T = T;
  $$('#tbl thead th').forEach(h => h.addEventListener('click', ev => { if (ev.target.dataset.def) return; const k = h.dataset.k; if (S.sort === k) S.dir *= -1; else { S.sort = k; S.dir = k.startsWith('cp') ? 1 : -1; } renderAds(); }));
  $$('#tbl tbody tr.has').forEach(r => r.addEventListener('click', ev => { if (ev.target.closest('td.c')) return; const p = r.dataset.p; S.open.has(p) ? S.open.delete(p) : S.open.add(p); renderAds(); }));
  $$('#tbl tbody td.c').forEach(td => td.addEventListener('click', () => { const tr = td.parentNode, o = tr.dataset.p ? N[tr.dataset.p] : T; leadList(o.ids[td.dataset.m], `${(DEF[td.dataset.m] || [td.dataset.m])[0]} · ${tr.dataset.p ? tr.dataset.p.split('›').slice(-1)[0] : 'Total'}`); }));
  notesAds(N);
}
function notesAds(N) {
  const un = Object.entries(N).filter(([p]) => p.split('›').length === 2 && (p.endsWith('›Unattributed') || p.endsWith('Old Meta account (spend not readable)')));
  $('#anotes').innerHTML = `<div><h4>Unattributed, shown honestly</h4><ul>${un.map(([p, o]) => `<li><b>${esc(p.replace('›', ' › '))}</b>: ${fmtN(o.leads)} leads, ${fmtN(o.sb)} Strats, ${fmtN(o.cb)} Scopes booked, ${fmtN(o.ch)} held</li>`).join('') || '<li>None in this range.</li>'}</ul></div>
  <div><h4>How to read it</h4><ul><li>Small % under a count = conversion from the step before it.</li><li><b>none yet</b> = money spent and none of that step yet.</li><li><b>spend not readable</b> = old Meta account (no access), <b>no lead tracking</b> = IG post boosts. Both are left out of every cost per step.</li><li>Sort by <b>Cost per qualified Strat</b> or <b>Cost per Scope held</b> to find winners (click the header, lowest first).</li></ul></div>
  <div><h4>Basis</h4><ul><li>${S.basis === 'cohort' ? '<b>Lead cohort</b>: leads created in the range and every step they have reached so far.' : '<b>Activity date</b>: each step counted on the day it happened.'}</li><li>Days are US Eastern; lead times show Madrid and ET.</li></ul></div>`;
}
function trend(a, b) {
  const n = b - a + 1, W = Math.max(320, $('#trend').clientWidth || 600), H = 150, pl = 40, pr = 34, pt = 8, pb = 20;
  const sp = Array(n).fill(0), ld = Array(n).fill(0), sb = Array(n).fill(0), cb = Array(n).fill(0);
  for (const [d, i, s] of P.sp) if (d >= a && d <= b && platOk(P.ents[i].k[0])) sp[d - a] += s;
  for (const L of P.leads) {
    if (!platOk(P.ents[L.a[S.model]].k[0])) continue;
    if (L.cd != null && L.cd >= a && L.cd <= b) ld[L.cd - a]++;
    const f = (arr, out) => { const s = new Set(arr.filter(d => d >= a && d <= b)); s.forEach(d => out[d - a]++); };
    f(L.m.sb, sb); f(L.m.cb, cb);
  }
  const ms = Math.max(1, ...sp), ml = Math.max(1, ...ld, ...sb), bw = (W - pl - pr) / n;
  const y1 = v => pt + (H - pt - pb) * (1 - v / ms), y2 = v => pt + (H - pt - pb) * (1 - v / ml);
  let s = `<svg width="${W}" height="${H}" role="img">`;
  for (let i = 0; i < n; i++) {
    const x = pl + i * bw;
    s += `<rect x="${x + bw * .15}" y="${y1(sp[i])}" width="${bw * .7}" height="${H - pb - y1(sp[i])}" fill="#2b3a5c" rx="2" data-i="${i}"></rect>`;
    if (n <= 31 || i % Math.ceil(n / 15) === 0) s += `<text x="${x + bw / 2}" y="${H - 5}" text-anchor="middle">${dayLabel(a + i).split(' ')[0]}</text>`;
  }
  const line = (arr, col) => `<polyline fill="none" stroke="${col}" stroke-width="2" points="${arr.map((v, i) => `${pl + i * bw + bw / 2},${y2(v)}`).join(' ')}"></polyline>` + arr.map((v, i) => v ? `<circle cx="${pl + i * bw + bw / 2}" cy="${y2(v)}" r="2.6" fill="${col}"></circle>` : '').join('');
  s += line(ld, '#60a5fa') + line(sb, '#ff3b3b') + line(cb, '#34d399');
  s += `<text x="4" y="${pt + 8}">${fmt$(ms)}</text><text x="${W - 4}" y="${pt + 8}" text-anchor="end">${ml}</text>`;
  for (let i = 0; i < n; i++) s += `<rect x="${pl + i * bw}" y="0" width="${bw}" height="${H - pb}" fill="transparent" class="hov" data-i="${i}"></rect>`;
  $('#trend').innerHTML = s + '</svg>';
  $$('#trend .hov').forEach(r => { const i = +r.dataset.i; r.addEventListener('mousemove', e => tip(e, `<b>${dayLabel(a + i)}</b><br>Spend ${fmt$(sp[i])}<br>Leads ${ld[i]} · Strats booked ${sb[i]} · Scopes booked ${cb[i]}`)); r.addEventListener('mouseleave', () => $('#tip').style.display = 'none'); });
}
function tip(e, h) { const t = $('#tip'); t.innerHTML = h; t.style.display = 'block'; t.style.left = Math.min(e.clientX + 14, innerWidth - 220) + 'px'; t.style.top = (e.clientY + 14) + 'px'; }

// ---------------- drawer ----------------
function drawer(title, sub, html) { $('#drt').textContent = title; $('#drs').innerHTML = sub || ''; $('#drb').innerHTML = html; $('#dr').classList.add('on'); $('#ov').classList.add('on'); $('#drb').scrollTop = 0; }
function closeDrawer() { $('#dr').classList.remove('on'); $('#ov').classList.remove('on'); }
function srcPath(L, m = S.model) { const k = P.ents[L.a[m]].k; return k.filter(Boolean).join(' › '); }
function leadList(ids, title) {
  ids = [...new Set(ids || [])];
  ids.sort((x, y) => (P.leads[y].ct || '').localeCompare(P.leads[x].ct || ''));
  drawer(title, `${ids.length} lead${ids.length === 1 ? '' : 's'} · ${S.basis === 'cohort' ? 'lead cohort' : 'activity date'} · ${esc(rangeText())}`,
    `<ul class="ll">${ids.map(i => { const L = P.leads[i]; return `<li data-l="${i}"><div>${esc(L.n || L.e || 'Unknown')}<small>${esc(L.co || '')}${L.co ? ' · ' : ''}${esc(srcPath(L))}</small></div><div class="num" style="color:var(--dim)">${dfmt(L.ct)}</div></li>`; }).join('') || '<li>None</li>'}</ul>`);
  $$('#drb .ll li[data-l]').forEach(li => li.addEventListener('click', () => leadCard(+li.dataset.l)));
}
const EVC = {created: '#60a5fa', strat_booked: '#fbbf24', strat_showed: '#34d399', strat_noshow: '#ff3b3b', strat_cancelled: '#ff6b5b', scope_booked: '#a78bfa', scope_held: '#34d399', scope_noshow: '#ff3b3b', scope_cancelled: '#ff6b5b', align_booked: '#f472b6', align_held: '#34d399', won: '#34d399', payment: '#2dd4bf', deal: '#94a3b8', stage: '#94a3b8'};
function leadCard(i) {
  const L = P.leads[i];
  const q = L.q === 1 ? '<span class="good">Quality lead</span>' : L.q === 0 ? '<span class="bad">Not quality</span>' : '<span class="z">Revenue unknown (no revenue band, no tag)</span>';
  const att = ['rule', 'first', 'last'].map(m => `<div>${{rule: 'Paid touch wins', first: 'First touch', last: 'Last touch'}[m]}</div><div>${esc(srcPath(L, m))}${L.ah && L.ah[m] === 'ad id' ? ' <span class="chip">matched by ad ID</span>' : ''}${P.ents[L.a[m]].ids.rule ? ' <span class="tag rule">attributed by rule</span>' : ''}</div>`).join('');
  const last = (L.ev || []).filter(e => e[0] && new Date(e[0]) <= new Date()).slice(-1)[0];
  const touches = (L.tc || []).map(t => `<div class="touch"><b>${t.k}</b>${esc(t.page || '(no page)')}${t.ref ? `<br><span class="z">referrer</span> ${esc(t.ref)}` : ''}${Object.keys(t.utm || {}).length ? '<br>' + Object.entries(t.utm).map(([k, v]) => `<span class="z">${esc(k)}</span> ${esc(v)}`).join(' · ') : ''}${t.how ? `<br><span class="z">via</span> ${esc(t.how)}` : ''}</div>`).join('') || '<div class="z">GHL has no page-visit attribution for this contact.</div>';
  const cf = Object.entries(L.cf || {}).map(([k, v]) => `<div>${esc(k)}</div><div>${esc(v)}</div>`).join('');
  drawer(L.n || L.e || 'Unknown lead', `${esc(L.e)}${L.co ? ' · ' + esc(L.co) : ''}${L.cn ? ' · ' + esc(L.cn) : ''}`,
    `<div class="kv"><div>Created</div><div>${tfmt(L.ct)}</div><div>Quality</div><div>${q}${L.rb ? ' · ' + esc(L.rb) : ''}${L.sql ? ' · SQL? ' + esc(L.sql) : ''}</div>
     ${L.qr ? `<div>Qualified Strat</div><div>yes (${esc(L.qr)})</div>` : ''}<div>Stage</div><div>${esc(L.stage || '–')}</div><div>Owner</div><div>${esc(L.owner || '–')}</div>
     <div>Deal value</div><div>${L.val ? fmt$(L.val) : '–'}</div><div>Last activity</div><div>${last ? esc(last[2]) + ' · ' + tfmt(last[0], false) : '–'}</div><div>GHL source</div><div>${esc(L.src || '–')}</div>
     ${L.dup ? `<div>Duplicate</div><div>same email/phone as an earlier lead; not counted twice</div>` : ''}</div>
     <h5>Where they came from</h5><div class="kv">${att}</div>
     <h5>Timeline</h5><div class="tl">${(L.ev || []).map(e => `<div class="e" style="--c:${EVC[e[1]] || '#4b5563'}"><div>${esc(e[2])}</div><div class="t">${tfmt(e[0])}</div></div>`).join('')}</div>
     <h5>Page visits GHL recorded</h5>${touches}
     ${cf ? `<h5>Tracking fields</h5><div class="kv">${cf}</div>` : ''}
     ${(L.tg || []).length ? `<h5>Tags</h5><div class="chips">${L.tg.map(t => `<span class="chip">${esc(t)}</span>`).join('')}</div>` : ''}
     <h5>Links</h5><a href="${esc(L.ghl)}" target="_blank" rel="noopener noreferrer" class="pill" style="text-decoration:none">Open contact in GHL ↗</a>`);
}

// ---------------- LEADS view ----------------
function renderLeads() {
  const [a, b] = rng(); const inr = d => d != null && d >= a && d <= b;
  const q = S.lq.trim().toLowerCase();
  let rows = P.leads.map((L, i) => [L, i]).filter(([L]) => {
    if (S.lscope === 'created' && !inr(L.cd)) return false;
    if (S.lscope === 'active') { const M = L.m; if (!(inr(L.cd) || ['sb', 'ss', 'cb', 'ch', 'ab', 'ah'].some(k => M[k].some(inr)) || inr(M.w))) return false; }
    const k = P.ents[L.a[S.model]].k;
    if (S.lch && k[0] !== S.lch) return false;
    if (!platOk(k[0]) && S.plat !== 'all' && S.lch === '') { /* platform filter applies */ return false; }
    if (S.lms) { if (S.lms === 'ql') { if (L.q !== 1) return false; } else if (S.lms === 'qu') { if (L.q != null) return false; } else if (S.lms === 'w') { if (L.m.w == null) return false; } else if (!L.m[S.lms].length) return false; }
    if (q) { const hay = (L.n + ' ' + L.e + ' ' + L.co + ' ' + k.join(' ') + ' ' + L.stage + ' ' + L.owner).toLowerCase(); if (!hay.includes(q)) return false; }
    return true;
  });
  const key = {ct: L => L.ct || '', n: L => (L.n || '').toLowerCase(), src: L => srcPath(L), st: L => L.stage || '', q: L => L.q == null ? -1 : L.q, last: L => (L.ev || []).slice(-1)[0]?.[0] || ''}[S.lsort] || (L => L.ct || '');
  rows.sort(([x], [y]) => { const vx = key(x), vy = key(y); return (vx < vy ? -1 : vx > vy ? 1 : 0) * S.ldir; });
  $('#lcount').textContent = `${rows.length} lead${rows.length === 1 ? '' : 's'}`;
  const hd = [['ct', 'Created'], ['n', 'Lead'], ['src', 'Source › ad set › ad'], ['q', 'Quality'], ['', 'Journey'], ['st', 'Stage · owner'], ['last', 'Last activity']];
  $('#ltbl thead').innerHTML = `<tr>${hd.map(([k, l]) => `<th data-k="${k}" class="${S.lsort === k ? 'sorted' : ''}">${l}${S.lsort === k ? (S.ldir < 0 ? ' ↓' : ' ↑') : ''}</th>`).join('')}</tr>`;
  const chip = (on, lab, cls = 'y', t = '') => `<span class="m ${on ? cls : ''}" title="${t}">${lab}</span>`;
  $('#ltbl tbody').innerHTML = rows.slice(0, S.llim).map(([L, i]) => {
    const M = L.m, k = P.ents[L.a[S.model]].k, last = (L.ev || []).filter(e => new Date(e[0]) <= new Date()).slice(-1)[0];
    const showed = M.ss.length > 0, ns = M.sn.length > 0 && !showed;
    return `<tr data-l="${i}" class="has"><td class="num">${dfmt(L.ct)}</td><td><b>${esc(L.n || L.e || 'Unknown')}</b><br><span class="z">${esc(L.co || L.e || '')}</span></td>
     <td><span class="dot" style="background:${CC[k[0]] || '#666'}"></span>${esc(k.slice(1).filter(Boolean).join(' › ') || k[0])}${P.ents[L.a[S.model]].ids.rule ? ' <span class="tag rule">rule</span>' : ''}</td>
     <td>${L.q === 1 ? '<span class="good">Yes</span>' : L.q === 0 ? '<span class="z">No</span>' : '<span class="z">Revenue unknown</span>'}${L.rb ? `<br><span class="z">${esc(L.rb)}</span>` : ''}</td>
     <td style="white-space:nowrap">${chip(M.sb.length, 'S', 'u', 'Strat booked')}${chip(showed || ns, showed ? '✓' : '✗', showed ? 'y' : 'n', 'Strat showed / no-show')}${chip(M.qs.length, 'Q', 'y', 'Qualified Strat')}${chip(M.cb.length, 'Sc', 'u', 'Scope booked')}${chip(M.ch.length, 'H', 'y', 'Scope held')}${chip(M.ah.length, 'A', 'y', 'Alignment held')}${chip(M.w != null, 'W', 'y', 'Won')}</td>
     <td>${esc(L.stage || '–')}${L.owner ? `<br><span class="z">${esc(L.owner)}</span>` : ''}</td><td class="num">${last ? `${esc(last[2]).slice(0, 48)}<br><span class="z">${tfmt(last[0], false)}</span>` : ''}</td></tr>`;
  }).join('') || '<tr><td colspan="7" class="z">No leads match.</td></tr>';
  $('#lmore').style.display = rows.length > S.llim ? 'inline-block' : 'none';
  $$('#ltbl thead th').forEach(h => h.addEventListener('click', () => { const k = h.dataset.k; if (!k) return; if (S.lsort === k) S.ldir *= -1; else { S.lsort = k; S.ldir = -1; } renderLeads(); }));
  $$('#ltbl tbody tr[data-l]').forEach(r => r.addEventListener('click', () => leadCard(+r.dataset.l)));
}

// ---------------- SALES view ----------------
const OWNERS = ['Rian', 'Saloumeh', 'MXB', 'Jake'];
const OWN_LABEL = {MXB: 'Michael (MXB)', Jake: 'Jake Roper'};
function renderSales() {
  const [a, b] = rng(); const inr = d => d != null && d >= a && d <= b;
  const {N, T} = aggregate(a, b); derived(T);
  const rc = reconStrip(a, b); $('#src').innerHTML = rc.h; wireRecon($('#src'));
  const k = (l, v, s, def) => `<div class="kpi"><div class="l">${l}<span class="i" data-def="${def}">i</span></div><div class="v">${rc.bad ? '<span class="z">check</span>' : v}</div><div class="s">${s}</div></div>`;
  $('#skpis').innerHTML = k('Strats booked', fmtN(T.sb), `${fmtN(T.ss)} showed · ${fmtN(T.sn)} no-show`, 'sb') + k('Show rate', pct(T.showr), 'showed ÷ (showed + no-show), cancels left out', 'ss')
    + k('Qualified Strats', fmtN(T.qs), `${pct(dv(T.qs, T.ss))} of shows`, 'qs') + k('Same-day Scope %', pct(T.sdr), `${fmtN(T.sd)} of ${fmtN(T.ss)} shows booked a Scope that day`, 'sd')
    + k('Scopes held', fmtN(T.ch), `${fmtN(T.cb)} booked · ${pct(T.hr)} show rate (held ÷ held + no-show)`, 'ch') + k('Alignments held', fmtN(T.ah), `${fmtN(T.ab)} booked`, 'ah')
    + k('Won', fmtN(T.w), `${fmt$(T.rev)} deal value`, 'w') + k('Cash', fmt$(T.cash), 'payments from won leads', 'cash')
    + k('Stuck deals', fmtN(P.stuck.filter(s => platOk(P.ents[P.leads[s[0]].a[S.model]].k[0])).length), 'open, no stage move in 14+ days', 'stuck') + k('Cost per Scope held', T.cpch != null ? fmt$(T.cpch) : (NONE[costState(T, 'ch')] || ['–'])[0], `$${P.meta.target_scope} target is per Scope booked`, 'cpch');
  const steps = [['leads', 'Leads'], ['ql', 'Quality leads'], ['sb', 'Strats booked'], ['ss', 'Strats showed'], ['qs', 'Qualified Strats'], ['cb', 'Scopes booked'], ['ch', 'Scopes held'], ['ah', 'Alignments held'], ['w', 'Won']];
  const mx = Math.max(1, T.leads);
  $('#fun').innerHTML = steps.map(([kk, l], j) => { const v = T[kk], pv = j ? T[steps[j - 1][0]] : null, cost = cp(T, kk);
    return `<div class="r"><div>${l}<span class="i" data-def="${kk}">i</span></div><div class="bar0"><div style="width:${Math.max(0.4, v / mx * 100)}%"></div></div><div class="v c" data-m="${kk}"><b>${fmtN(v)}</b>${j ? pct(dv(v, pv)) : ''}${cost ? ` · ${fmt$(cost)}` : ''}</div></div>`; }).join('');
  $('#funleg').textContent = S.basis === 'cohort' ? 'lead cohort' : 'activity date';
  $$('#v-sales .bl').forEach(x => x.textContent = S.basis === 'cohort' ? 'leads created in range' : 'dated in range');
  $$('#fun .v.c').forEach(e => e.addEventListener('click', () => leadList(T.ids[e.dataset.m], (DEF[e.dataset.m] || [e.dataset.m])[0])));
  // show rate by confirmation, calls dated in range (past only)
  const coh = S.basis === 'cohort', inB = (li, day) => coh ? inr(P.leads[li].cd) : inr(day), bTxt = coh ? 'leads created in the range (lead cohort)' : 'calls / events dated in the range';
  const sr = P.strats.filter(r => inB(r[0], r[2]) && r[7] && platOk(P.ents[P.leads[r[0]].a[S.model]].k[0]));
  const grp = f => { const g = sr.filter(f), sh = g.filter(r => r[3] === 'showed').length, ns = g.filter(r => r[3] === 'noshow').length, cx = g.filter(r => r[3] === 'cancelled').length; return {n: g.length, sh, ns, cx, r: dv(sh, sh + ns + cx), r2: dv(sh, sh + ns)}; };
  const rowS = (l, g) => `<tr><td>${l}</td><td>${g.n}</td><td>${g.sh}</td><td>${g.ns}</td><td>${g.cx}</td><td>${pct(g.r2)}</td><td>${pct(g.r)}</td></tr>`;
  $('#showr').innerHTML = `<table><thead><tr><th>Calls</th><th>Total</th><th>Showed</th><th>No-show</th><th>Cancelled</th><th title="showed ÷ (showed + no-show)">Show rate</th><th title="showed ÷ (showed + no-show + cancelled)">Incl. cancels</th></tr></thead><tbody>
   ${rowS('Confirmed before call', grp(r => r[5] === 1))}${rowS('Not confirmed', grp(r => r[5] === 0))}${rowS('Confirmation unknown', grp(r => r[5] == null))}${rowS('<b>All</b>', grp(() => true))}</tbody></table>
   <p class="z" style="font-size:11.5px;margin-top:8px">Confirmed = the lead was in GHL stage “Strat” or ticked the confirm box before the call (daily sales-scorecard snapshots). Calls without a snapshot are “unknown”.</p>`;
  // owners
  const showRep = {}; for (const r of P.strats) if (r[3] === 'showed') showRep[r[0]] = r[4];
  const O = {}; const og = n => O[n] || (O[n] = {n: 0, sh: 0, ns: 0, cx: 0, qs: 0, sd: 0, cb: 0, ch: 0, cn: 0, al: 0, w: 0, wv: 0, stuck: 0, sv: 0});
  OWNERS.forEach(og);
  for (const r of sr) { const o = og(r[4]); o.n++; if (r[3] === 'showed') { o.sh++; const L = P.leads[r[0]]; if (L.m.qs.includes(r[2])) o.qs++; if (L.m.sd.includes(r[2])) o.sd++; } else if (r[3] === 'noshow') o.ns++; else if (r[3] === 'cancelled') o.cx++; }
  P.leads.forEach((L, i) => { if (!platOk(P.ents[L.a[S.model]].k[0])) return; if (coh && !inr(L.cd)) return;
    if (coh ? L.m.cb.length : L.m.cb.some(inr)) og(showRep[i] || 'No Strat show')['cb']++;
    if (L.m.w != null && (coh || inr(L.m.w))) { const o = og(L.owner || 'Unassigned'); o.w++; o.wv += L.m.rev; } });
  for (const r of P.scopes) if (inB(r[0], r[2]) && r[5] && platOk(P.ents[P.leads[r[0]].a[S.model]].k[0])) { const o = og(showRep[r[0]] || r[4]); if (r[3] === 'showed') o.ch++; else if (r[3] === 'noshow') o.cn++; }
  for (const r of P.aligns) if (inB(r[0], r[2]) && r[5] && r[3] === 'showed' && platOk(P.ents[P.leads[r[0]].a[S.model]].k[0])) og(showRep[r[0]] || r[4]).al++;
  for (const s of P.stuck) if (platOk(P.ents[P.leads[s[0]].a[S.model]].k[0])) { const o = og(s[3]); o.stuck++; o.sv += s[4]; }
  const ord = Object.keys(O).sort((x, y) => (OWNERS.indexOf(x) < 0 ? 99 : OWNERS.indexOf(x)) - (OWNERS.indexOf(y) < 0 ? 99 : OWNERS.indexOf(y)) || (O[y].n - O[x].n));
  $('#reps').innerHTML = `<div class="tw" style="border:0"><table class="reps"><thead><tr><th>Owner</th><th>Strat calls</th><th>Showed</th><th>No-show</th><th>Cancelled</th><th>Show rate</th><th>Qualified Strats</th><th title="Share of Strat shows that booked a Scope the same ET day">Same-day Scope %</th><th>Scopes booked</th><th>Scopes held</th><th>Alignments held</th><th>Won</th><th title="Open deals with no stage move in 14+ days, as of now (not date-filtered)">Stuck deals (now)</th></tr></thead><tbody>
   ${ord.map(n => { const o = O[n]; return `<tr><td>${esc(OWN_LABEL[n] || n)}</td><td>${o.n}</td><td>${o.sh}</td><td>${o.ns}</td><td>${o.cx}</td><td>${pct(dv(o.sh, o.sh + o.ns))}</td><td>${o.qs}</td><td>${o.sh ? pct(o.sd / o.sh) + ` <span class="z">${o.sd}</span>` : '–'}</td><td>${o.cb}</td><td>${o.ch}</td><td>${o.al}</td><td>${o.w}${o.wv ? ` <span class="z">${fmt$(o.wv)}</span>` : ''}</td><td class="${o.stuck ? 'c' : ''}" data-o="${esc(n)}">${o.stuck}${o.sv ? ` <span class="z">${fmt$(o.sv)}</span>` : ''}</td></tr>`; }).join('')}</tbody></table></div>
   <p class="z" style="font-size:11.5px;margin-top:8px">Date basis: ${bTxt}. Calls credited to the rep on the Strat. Scopes, Alignments credited to the rep who ran the lead's Strat. Won and stuck deals: Sales Pipeline owner. Stuck deals are a snapshot of today.</p>`;
  $$('#reps td[data-o].c').forEach(td => td.addEventListener('click', () => stuckList(td.dataset.o)));
  // scope calls
  const sc = P.scopes.filter(r => inB(r[0], r[2]) && platOk(P.ents[P.leads[r[0]].a[S.model]].k[0]));
  const scg = st => sc.filter(r => r[3] === st).length;
  const past = sc.filter(r => r[5]);
  $('#sreps').innerHTML = `<div class="kv"><div>Scope calls (${coh ? 'leads created in range' : 'dated in range'})</div><div>${sc.length} (${past.length} already happened)</div><div>Held</div><div>${scg('showed')}</div><div>No-show</div><div>${scg('noshow')}</div><div>Cancelled</div><div>${scg('cancelled')}</div>
    <div>Still “confirmed”, in the past</div><div>${past.filter(r => !['showed', 'noshow', 'cancelled'].includes(r[3])).length} <span class="z">(status not updated in GHL)</span></div><div>Upcoming</div><div>${sc.filter(r => !r[5]).length}</div>
    <div>Held rate</div><div>${pct(dv(scg('showed'), scg('showed') + scg('noshow') + scg('cancelled')))}</div></div>`;
  // by source
  const lv = S.plat === 'all' ? 0 : 2;
  const srcRows = Object.entries(N).filter(([p]) => p.split('›').length === lv + 1).map(([p, o]) => [p, derived(o)]).filter(([, o]) => o.leads || o.sb || o.cb).sort((x, y) => y[1].leads - x[1].leads).slice(0, 25);
  $('#bysrc').innerHTML = `<thead><tr><th>${lv ? 'Ad set' : 'Source'}</th><th>Leads</th><th>Quality</th><th>Strats</th><th title="Strats booked ÷ leads">Lead → Strat %</th><th>Strats showed</th><th>Qualified Strats</th><th>Scopes booked</th><th title="Scopes booked ÷ qualified Strats">Qualified Strat → Scope %</th><th>Scopes held</th><th>Won</th><th>Cost per qualified Strat</th><th>Cost per Scope held</th></tr></thead><tbody>
   ${srcRows.map(([p, o]) => `<tr><td title="${esc(p)}">${esc(nmT(p.split('›').slice(-1)[0]))}</td><td>${o.leads}</td><td>${o.ql}</td><td>${o.sb}</td><td>${pct(dv(o.sb, o.leads))}</td><td>${o.ss}</td><td>${o.qs}</td><td>${o.cb}</td><td>${pct(dv(o.cb, o.qs))}</td><td>${o.ch}</td><td>${o.w}</td><td>${o.cpqs != null ? fmt$(o.cpqs) : `<span class="z">${(NONE[costState(o, 'qs')] || ['–'])[0]}</span>`}</td><td>${o.cpch != null ? fmt$(o.cpch) : `<span class="z">${(NONE[costState(o, 'ch')] || ['–'])[0]}</span>`}</td></tr>`).join('')}</tbody>`;
  // sales list
  const sl = P.leads.map((L, i) => [L, i]).filter(([L]) => L.m.w != null && (S.basis === 'cohort' ? inr(L.cd) : inr(L.m.w)) && platOk(P.ents[L.a[S.model]].k[0]));
  $('#slist').innerHTML = sl.length ? `<ul class="ll">${sl.map(([L, i]) => `<li data-l="${i}"><div>${esc(L.n)} <small>${esc(srcPath(L))} · owner ${esc(L.owner || '–')}</small></div><div class="num">${L.m.rev ? fmt$(L.m.rev) : '<span class="z">no value</span>'} · ${fmt$(L.m.cash.reduce((s, x) => s + x[1], 0))} cash</div></li>`).join('')}</ul>` : '<div class="empty">No sales in this range for this filter.</div>';
  $$('#slist li[data-l]').forEach(li => li.addEventListener('click', () => leadCard(+li.dataset.l)));
}
function stuckList(owner) {
  const L = P.stuck.filter(s => s[3] === owner).sort((a, b) => b[2] - a[2]);
  drawer(`Stuck deals · ${owner}`, 'Open Sales Pipeline deals with no stage move in 14+ days', `<ul class="ll">${L.map(s => `<li data-l="${s[0]}"><div>${esc(P.leads[s[0]].n)}<small>${esc(s[1])} · ${s[2]} days</small></div><div class="num">${s[4] ? fmt$(s[4]) : ''}</div></li>`).join('')}</ul>`);
  $$('#drb .ll li[data-l]').forEach(li => li.addEventListener('click', () => leadCard(+li.dataset.l)));
}

// ---------------- SOURCES view ----------------
function renderSources() {
  const [a, b] = rng();
  const G = {}, AI = {};
  for (const [d, ch, src, ses, us, eng, ke] of P.ga) { if (d < a || d > b) continue; const g = G[ch] || (G[ch] = [0, 0, 0, 0]); g[0] += ses; g[1] += us; g[2] += eng; g[3] += ke;
    if (/AI Assistant|Referral/.test(ch)) { const k = ch.startsWith('AI') ? 'AI · ' + src : 'Referral · ' + src; const x = AI[k] || (AI[k] = [0, 0]); x[0] += ses; x[1] += eng; } }
  const tot = Object.values(G).reduce((s, g) => s + g[0], 0) || 1;
  $('#ga').innerHTML = `<table><thead><tr><th>Channel</th><th>Sessions</th><th>Share</th><th>Users</th><th>Engaged</th><th title="GA4 key events (booking event not live yet)">Key events</th></tr></thead><tbody>${Object.entries(G).sort((x, y) => y[1][0] - x[1][0]).map(([c, g]) => `<tr><td>${esc(c)}</td><td>${fmtN(g[0])}</td><td>${pct(g[0] / tot)}</td><td>${fmtN(g[1])}</td><td>${pct(dv(g[2], g[0]))}</td><td>${fmtN(g[3])}</td></tr>`).join('')}</tbody></table>`;
  $('#gaai').innerHTML = `<table><thead><tr><th>Source</th><th>Sessions</th><th>Engaged</th></tr></thead><tbody>${Object.entries(AI).sort((x, y) => y[1][0] - x[1][0]).slice(0, 20).map(([c, g]) => `<tr><td>${esc(c)}</td><td>${fmtN(g[0])}</td><td>${pct(dv(g[1], g[0]))}</td></tr>`).join('') || '<tr><td colspan="3" class="z">None in range</td></tr>'}</tbody></table>`;
  const sv = S.plat; S.plat = 'all'; const {N} = aggregate(a, b); S.plat = sv;
  const rows = Object.entries(N).filter(([p]) => p.split('›').length <= 2).map(([p, o]) => [p, derived(o)]).filter(([, o]) => o.leads || o.sb || o.cb || o.spend);
  const top = rows.filter(([p]) => !p.includes('›')).sort((x, y) => y[1].leads - x[1].leads);
  const out = [];
  for (const [p, o] of top) { out.push([p, o, 0]); rows.filter(([q]) => q.startsWith(p + '›')).sort((x, y) => y[1].leads - x[1].leads).forEach(([q, o2]) => out.push([q, o2, 1])); }
  $('#srct').innerHTML = `<thead><tr><th>Source</th><th>Spend</th><th>Leads</th><th>Quality leads</th><th>Strats booked</th><th>Strats showed</th><th>Qualified Strats</th><th>Scopes booked</th><th>Scopes held</th><th>Won</th><th>Cash</th></tr></thead><tbody>
   ${out.map(([p, o, l]) => `<tr class="l${l}"><td>${l ? '' : `<span class="dot" style="background:${CC[p] || '#666'}"></span>`}${esc(nmT(p.split('›').slice(-1)[0]) || '(none)')}</td><td>${o.spend ? fmt$(o.spend) : '<span class="z">–</span>'}</td><td>${o.leads}</td><td>${o.ql}</td><td>${o.sb}</td><td>${o.ss}</td><td>${o.qs}</td><td>${o.cb}</td><td>${o.ch}</td><td>${o.w}</td><td>${o.cash ? fmt$(o.cash) : '<span class="z">–</span>'}</td></tr>`).join('')}</tbody>`;
}

// ---------------- REPORTS (weekly) ----------------
function recRows(text) { // find ad sets / campaigns mentioned in a rec, by LinkedIn/Meta id or exact name
  const t = (text || '').toLowerCase(), out = [];
  for (const p of Object.keys(window.__allN || {})) {
    const parts = p.split('›'); if (parts.length !== 3 || !PAID.includes(parts[0])) continue;
    const e = entOf(p); const id = e && e.ids && (e.ids.adset || '');
    if ((id && t.includes(String(id))) || (parts[2].length > 6 && t.includes(parts[2].toLowerCase()))) out.push(p);
  }
  return out.slice(0, 3);
}
function weekly() {
  const n = P.days.length, b = n - 2, a = Math.max(0, b - 13); const sv = S.plat; S.plat = 'all'; const AN = aggregate(a, b).N; S.plat = sv; Object.values(AN).forEach(derived); window.__allN = AN;
  const W = [...(P.weeks || [])].sort((x, y) => y.start.localeCompare(x.start));
  if (!W.length) { $('#weeks').innerHTML = '<div class="empty">No weeks saved yet.</div>'; return; }
  $('#weeks').innerHTML = W.map(w => {
    const h = (w.headline || {}).All || {}; const recs = (w.recs || []).filter(r => S.wf === 'all' || r.status === S.wf);
    const cnt = ['Open', 'Done', 'Declined'].map(s => { const k = (w.recs || []).filter(r => r.status === s).length; return k ? `<span class="st ${s}">${k} ${s}</span>` : ''; }).join('');
    const chs = Object.entries(w.headline || {}).filter(([c]) => c !== 'All').sort((x, y) => (y[1].spend || 0) - (x[1].spend || 0) || (y[1].leads || 0) - (x[1].leads || 0));
    const op = S.wopen.has(w.start);
    const recH = r => { const refs = (r.refs && r.refs.length) ? r.refs : recRows(r.text + ' ' + (r.note || '')).map(p => ({p, m: 'cpqs'}));
      return refs.map(({p, m}) => { const o = AN[p] || derived(zero()), col = COLS.find(c => c[0] === m) || [m, m], nm = p.split('›').slice(-1)[0];
        const base = {cpl: 'leads', cpql: 'ql', cpsb: 'sb', cpqs: 'qs', cpcb: 'cb', cpch: 'ch'}[m];
        const v = col[2] === '$' ? (o[m] != null ? fmt$(o[m]) : (NONE[costState(o, base)] || ['–'])[0]) : fmtN(o[m]);
        return `<div class="meta recnum">Now, last 14 days (${S.basis === 'cohort' ? 'lead cohort' : 'event date'}) · <b>${esc(nmT(nm))}</b>: <b class="big">${col[1]} ${v}</b> <span class="z">(${fmt$(o.spend)} spend · ${fmtN(o.leads)} leads · ${fmtN(o.qs)} qualified Strats · ${fmtN(o.cb)} Scopes booked · ${fmtN(o.ch)} held)</span> <a href="#" class="golink" data-p="${esc(p)}">open row →</a></div>`; }).join(''); };
    return `<div class="wk ${op ? 'open' : ''}" data-w="${w.start}"><div class="h"><span class="car">›</span><div class="lab">${esc(w.label)}<small>${w.partial ? 'in progress · ' : ''}snapshot ${w.frozen_at ? dfmt(w.frozen_at) : ''}</small></div>
    <div class="hl num"><span><b>${fmt$(h.spend)}</b>spend</span><span><b>${fmtN(h.leads)}</b>leads</span><span><b>${fmtN(h.strats)}</b>Strats</span><span><b>${fmtN(h.scopes)}</b>Scopes booked</span><span><b>${fmtN(h.scopes_held)}</b>held</span><span><b class="${h.cp_scope != null ? (h.cp_scope <= 600 ? 'good' : 'bad') : ''}">${fmt$(h.cp_scope)}</b>per Scope</span><span><b>${fmtN(h.sales)}</b>${h.sales === 1 ? 'sale' : 'sales'}</span></div><div class="cnt">${cnt}</div></div>
    <div class="b"><table class="wkt num"><thead><tr><th>Channel</th><th>Spend</th><th>Leads</th><th>Cost per lead</th><th>Strats booked</th><th>Showed</th><th>Qualified</th><th>Scopes booked</th><th>Cost per Scope</th><th>Scopes held</th><th>Won</th><th>Cash</th></tr></thead><tbody>
    ${chs.map(([c, v]) => { const wc = (x, n) => x != null ? fmt$(x) : (v.spend && !v.cost_spend ? '<span class="z">no lead tracking</span>' : (n && v.unreadable_leads >= n ? '<span class="z">spend not readable</span>' : (v.spend ? '<span class="z">none yet</span>' : '<span class="z">–</span>')));
      return `<tr><td><span class="dot" style="background:${CC[c] || '#666'}"></span>${esc(c)}</td><td>${fmt$(v.spend)}${v.cost_spend != null && v.spend - v.cost_spend > 1 ? `<br><span class="z" title="IG post boosts, no lead tracking">${fmt$(v.spend - v.cost_spend)} IG boosts</span>` : ''}</td><td>${fmtN(v.leads)}${v.unreadable_leads ? `<br><span class="z" title="From the old Meta account: spend not readable, left out of cost">${fmtN(v.unreadable_leads)} old acct</span>` : ''}</td><td>${wc(v.cpl, v.leads)}</td><td>${fmtN(v.strats)}</td><td>${fmtN(v.showed)}</td><td>${fmtN(v.qual_strats)}</td><td>${fmtN(v.scopes)}</td><td>${wc(v.cp_scope, v.scopes)}</td><td>${fmtN(v.scopes_held)}</td><td>${fmtN(v.sales)}</td><td>${fmt$(v.cash)}</td></tr>`; }).join('')}</tbody></table>
    <div class="cols"><div><h5>Recommended next steps</h5>${recs.length ? recs.map(r => `<div class="rec"><span class="st ${r.status}">${r.status}</span><div>${esc(r.text)}<div class="meta">${r.follow_up ? 'Follow up ' + esc(r.follow_up) : ''}${r.note ? ' · ' + esc(r.note) : ''}</div>${recH(r)}</div></div>`).join('') : '<div class="empty">None for this filter.</div>'}</div>
    <div><h5>What we actually did</h5>${(w.changes || []).length ? w.changes.map(c => `<div class="chg"><div class="w">${esc(c.when)}${c.by ? ' · ' + esc(c.by) : ''}</div><div>${esc(c.what)}</div>${c.why ? `<div class="ba">Why: ${esc(c.why)}</div>` : ''}${c.before || c.after ? `<div class="ba num">${esc(c.before)} → ${esc(c.after)}</div>` : ''}</div>`).join('') : '<div class="empty">No changes logged.</div>'}</div></div>
    <div class="meta" style="color:var(--dim);font-size:11.5px;margin-top:12px">Week numbers: ${w.method === 'v2' ? 'rebuilt with today\'s counting (GHL truth, event dates, paid-touch rule). Cost per step leaves out IG boosts (no lead tracking) and old-Meta leads (spend not readable).' : 'old portal counting (frozen when saved).'} Each rec shows its live 14-day number.</div></div></div>`;
  }).join('');
  $$('.wk .h').forEach(h => h.addEventListener('click', () => { const w = h.parentNode.dataset.w; S.wopen.has(w) ? S.wopen.delete(w) : S.wopen.add(w); weekly(); }));
  $$('.golink').forEach(a => a.addEventListener('click', e => { e.preventDefault(); const p = a.dataset.p, parts = p.split('›'); S.plat = 'all'; S.r = '14'; S.adq = parts.length > 2 ? parts[2] : (parts[1] || ''); $('#adq').value = S.adq; for (let i = 1; i < parts.length; i++) S.open.add(parts.slice(0, i).join('›')); syncBar(); show('ads'); }));
}

// ---------------- DEFINITIONS ----------------
function renderDefs() {
  $('#defs').innerHTML = P.defs.map(([k, l, t]) => `<dt id="def-${k}">${esc(l)}</dt><dd>${esc(t)}</dd>`).join('') + P.notes.map(([l, t]) => `<dt>${esc(l)}</dt><dd>${esc(t)}</dd>`).join('');
  $('#gaps').innerHTML = (P.gaps || []).map(g => `<li>${g}</li>`).join('');
}
function defPop(k) { const d = DEF[k]; if (!d) return; drawer(d[0], 'Definition', `<p style="font-size:13.5px;line-height:1.55">${esc(d[1])}</p><p style="margin-top:14px"><a href="#" id="alldefs" class="pill" style="text-decoration:none">All definitions →</a></p>`); $('#alldefs').addEventListener('click', e => { e.preventDefault(); closeDrawer(); show('defs'); }); }

// ---------------- shell ----------------
function rangeText() { const [a, b] = rng(); return `${dayLabel(a)} – ${dayLabel(b)} ET${b === P.days.length - 1 ? ' (today partial)' : ''}`; }
function syncBar() {
  $$('#rng button').forEach(x => x.classList.toggle('on', x.dataset.r === S.r)); $('#cust').style.display = S.r === 'c' ? 'flex' : 'none';
  $$('#plat button').forEach(x => x.classList.toggle('on', x.dataset.p === S.plat)); $('#model').value = S.model; $('#basis').value = S.basis;
  $('#tdsw').classList.toggle('on', S.today); $('#fullsw').classList.toggle('on', S.full); $('#zsw').classList.toggle('on', S.hz);
  $('#rtxt').textContent = `${rangeText()} · ${S.basis === 'cohort' ? 'Lead cohort' : 'Activity date'}`;
}
function show(v) {
  S.view = v; $$('#tabs button').forEach(b => b.classList.toggle('on', b.dataset.v === v));
  $$('section').forEach(s => s.style.display = s.id === 'v-' + v ? 'block' : 'none');
  $('#gbar').style.display = ['weekly', 'defs'].includes(v) ? 'none' : 'flex';
  render();
}
function render() {
  syncBar();
  try {
    ({ads: renderAds, leads: renderLeads, sales: renderSales, sources: renderSources, weekly, defs: renderDefs})[S.view]();
  } catch (e) { console.error(e); $('#err2').style.display = 'block'; $('#err2').textContent = 'Something broke while drawing this view: ' + e.message; }
}
function start() {
  $('#gate').style.display = 'none'; $('#app').style.display = 'block';
  for (const [k, l, t] of P.defs) DEF[k] = [l, t];
  DEF.stuck = ['Stuck deals', 'Open Sales Pipeline deals (not Lost / Unqualified) whose stage has not changed in more than 14 days. Click a number to see them.'];
  const g = new Date(P.meta.generated);
  $('#upd').innerHTML = `Last refreshed ${g.toLocaleString('en-GB', {timeZone: MAD, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'})} Madrid · ${g.toLocaleString('en-US', {timeZone: NY, hour: 'numeric', minute: '2-digit'})} ET`;
  const d0 = $('#d0'), d1 = $('#d1'); d0.min = d1.min = P.days[0]; d0.max = d1.max = P.days[P.days.length - 1];
  d0.value = P.days[Math.max(0, P.days.length - 15)]; d1.value = P.days[P.days.length - 2];
  $('#lch').innerHTML = '<option value="">All</option>' + P.meta.channels.map(c => `<option>${esc(c)}</option>`).join('');
  $$('#tabs button').forEach(b => b.addEventListener('click', () => show(b.dataset.v)));
  $$('#rng button').forEach(b => b.addEventListener('click', () => { S.r = b.dataset.r; render(); }));
  [d0, d1].forEach(x => x.addEventListener('change', () => { S.r = 'c'; render(); }));
  $$('#plat button').forEach(b => b.addEventListener('click', () => { S.plat = b.dataset.p; render(); }));
  $('#model').addEventListener('change', e => { S.model = e.target.value; render(); });
  $('#basis').addEventListener('change', e => { S.basis = e.target.value; render(); });
  $('#tdsw').addEventListener('click', () => { S.today = !S.today; render(); });
  $('#fullsw').addEventListener('click', () => { S.full = !S.full; render(); });
  $('#zsw').addEventListener('click', () => { S.hz = !S.hz; render(); });
  $('#expall').addEventListener('click', () => { const N = window.__N || {}; const all = Object.keys(N).filter(p => p.split('›').length < 3); const allOpen = all.every(p => S.open.has(p)); all.forEach(p => allOpen ? S.open.delete(p) : S.open.add(p)); $('#expall').textContent = allOpen ? 'Expand all' : 'Collapse all'; render(); });
  let t1; $('#adq').addEventListener('input', e => { clearTimeout(t1); t1 = setTimeout(() => { S.adq = e.target.value; render(); }, 150); });
  let t2; $('#lq').addEventListener('input', e => { clearTimeout(t2); t2 = setTimeout(() => { S.lq = e.target.value; S.llim = 150; render(); }, 150); });
  $('#lscope').addEventListener('change', e => { S.lscope = e.target.value; render(); });
  $('#lms').addEventListener('change', e => { S.lms = e.target.value; render(); });
  $('#lch').addEventListener('change', e => { S.lch = e.target.value; render(); });
  $('#lmore').addEventListener('click', () => { S.llim += 300; render(); });
  $$('#wf button').forEach(b => b.addEventListener('click', () => { S.wf = b.dataset.s; $$('#wf button').forEach(x => x.classList.toggle('on', x === b)); weekly(); }));
  $('#drx').addEventListener('click', closeDrawer); $('#ov').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
  document.addEventListener('click', e => { const d = e.target.closest('[data-def]'); if (d) { e.stopPropagation(); e.preventDefault(); defPop(d.dataset.def); } }, true);
  let rz; addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(() => P && S.view === 'ads' && render(), 200); });
  const h = (location.hash || '').slice(1); show(['ads', 'leads', 'sales', 'sources', 'weekly', 'defs'].includes(h) ? h : 'ads');
}

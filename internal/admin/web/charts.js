'use strict';
// Dependency-free SVG charts in Zoraxy's dashboard style (flat fills, thin
// gradient ranking bars, donut with legend, status ring). No inline style
// attributes: the plugin's CSP forbids them, CSSOM via el.style is fine.
const SVG = 'http://www.w3.org/2000/svg';
// Category palette deliberately avoids the decision colours (blue = blocked, amber = recorded, red = error).
const PALETTE = ['#8B5CF6', '#0EA5C6', '#F97316', '#4B3FB8', '#EC4899', '#14B8A6', '#A16207', '#6366F1', '#9CA3AF'];
function el(tag, attrs = {}, children = []) {
 const n = document.createElementNS(SVG, tag);
 for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
 for (const c of children) n.append(c);
 return n;
}
function title(text) { const t = el('title'); t.textContent = text; return t; }
function nice(max) { if (max <= 0) return 1; const p = 10 ** Math.floor(Math.log10(max)); const f = max / p; const m = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10; return m * p; }
function fmt(n) { return Number(n).toLocaleString(); }

// Stacked bars. points: [{label, values:[...]}], series: [{name, color}].
export function bars(container, points, series, opts = {}) {
 // Width follows the real container so axis text keeps its pixel size on phones.
 const W = Math.max(container.clientWidth || 600, 300), H = 190, padL = 34, padB = 22, padT = 8, padR = 30;
 const innerW = W - padL - padR, innerH = H - padT - padB;
 const totals = points.map(p => p.values.reduce((a, b) => a + b, 0));
 const max = nice(Math.max(...totals, 0));
 const svg = el('svg', {viewBox: `0 0 ${W} ${H}`, class: 'chart bars', role: 'img', 'aria-label': opts.label || ''});
 for (const frac of [0, .5, 1]) {
  const y = padT + innerH - innerH * frac;
  svg.append(el('line', {x1: padL, x2: W - padR, y1: y, y2: y, class: 'grid'}));
  const t = el('text', {x: padL - 6, y: y + 4, class: 'axis', 'text-anchor': 'end'}); t.textContent = fmt(max * frac); svg.append(t);
 }
 const slot = innerW / Math.max(points.length, 1), bw = Math.max(slot * .66, 2);
 points.forEach((p, i) => {
  let y = padT + innerH;
  const x = padL + i * slot + (slot - bw) / 2;
  p.values.forEach((v, si) => {
   const h = max ? innerH * v / max : 0;
   y -= h;
   const r = el('rect', {x, y, width: bw, height: h, fill: series[si].color, rx: 1});
   r.append(title(`${p.label}: ${fmt(v)} ${series[si].name}`));
   svg.append(r);
  });
  if (totals[i] === 0) { const z = el('rect', {x, y: padT + innerH - 1, width: bw, height: 1, class: 'zero'}); z.append(title(`${p.label}: 0`)); svg.append(z); }
  if ((opts.every && i % opts.every === 0 && i + opts.every <= points.length - 1) || i === points.length - 1) { const last = i === points.length - 1; const t = el('text', {x: last ? x + bw : x + bw / 2, y: H - 6, class: 'axis', 'text-anchor': last ? 'end' : 'middle'}); t.textContent = p.label; svg.append(t); }
 });
 const legend = document.createElement('div'); legend.className = 'legend';
 series.forEach(s => { const i = document.createElement('span'); const sw = document.createElement('i'); sw.style.background = s.color; i.append(sw, s.name); legend.append(i); });
 container.replaceChildren(svg, legend);
 return totals.reduce((a, b) => a + b, 0);
}

// Donut with legend. items: [{label, value}]; returns total.
export function donut(container, items, opts = {}) {
 const total = items.reduce((a, b) => a + b.value, 0);
 const R = 46, r = 32, C = 50;
 const svg = el('svg', {viewBox: '0 0 100 100', class: 'chart donut', role: 'img', 'aria-label': opts.label || ''});
 if (!total) {
  svg.append(el('circle', {cx: C, cy: C, r: (R + r) / 2, class: 'track', fill: 'none', 'stroke-width': R - r}));
 } else {
  let a0 = -Math.PI / 2;
  items.forEach((it, i) => {
   if (!it.value) return;
   const a1 = a0 + 2 * Math.PI * it.value / total;
   const big = a1 - a0 > Math.PI ? 1 : 0;
   const p = (ang, rad) => `${C + rad * Math.cos(ang)} ${C + rad * Math.sin(ang)}`;
   const d = it.value === total
    ? `M ${p(a0, R)} A ${R} ${R} 0 1 1 ${p(a0 + Math.PI, R)} A ${R} ${R} 0 1 1 ${p(a0, R)} M ${p(a0, r)} A ${r} ${r} 0 1 0 ${p(a0 + Math.PI, r)} A ${r} ${r} 0 1 0 ${p(a0, r)} Z`
    : `M ${p(a0, R)} A ${R} ${R} 0 ${big} 1 ${p(a1, R)} L ${p(a1, r)} A ${r} ${r} 0 ${big} 0 ${p(a0, r)} Z`;
   const path = el('path', {d, fill: it.color || PALETTE[i % PALETTE.length], 'fill-rule': 'evenodd'});
   path.append(title(`${it.label}: ${fmt(it.value)} (${Math.round(100 * it.value / total)} %)`));
   svg.append(path);
   a0 = a1;
  });
 }
 const centre = el('text', {x: C, y: C + 5, class: 'donut-total', 'text-anchor': 'middle'}); centre.textContent = fmt(total); svg.append(centre);
 const legend = document.createElement('ul'); legend.className = 'legend-list';
 items.forEach((it, i) => {
  const li = document.createElement('li'); if (!it.value) li.className = 'zero'; const sw = document.createElement('i'); sw.style.background = it.color || PALETTE[i % PALETTE.length];
  const name = document.createElement('span'); name.textContent = it.label;
  const val = document.createElement('b'); val.textContent = total ? `${fmt(it.value)} · ${Math.round(100 * it.value / total)} %` : '0';
  li.append(sw, name, val); legend.append(li);
 });
 if (!items.length) { const li = document.createElement('li'); li.className = 'muted'; li.textContent = opts.empty || 'No data yet'; legend.append(li); }
 const wrap = document.createElement('div'); wrap.className = 'donut-wrap'; wrap.append(svg, legend);
 container.replaceChildren(wrap);
 return total;
}

// Status ring (0-100 %) like Wordfence's protection circle.
export function ring(container, pct, color) {
 const R = 39, C = 50, len = 2 * Math.PI * R;
 const svg = el('svg', {viewBox: '0 0 100 100', class: 'chart ring', role: 'img', 'aria-label': `Protection ${pct} %`});
 svg.append(el('circle', {cx: C, cy: C, r: R, class: 'track', fill: 'none', 'stroke-width': 14}));
 svg.append(el('circle', {cx: C, cy: C, r: R, fill: 'none', stroke: color, 'stroke-width': 14, 'stroke-linecap': 'round', 'stroke-dasharray': `${len * pct / 100} ${len}`, transform: `rotate(-90 ${C} ${C})`}));
 const t = el('text', {x: C, y: C + 7, class: 'ring-text', 'text-anchor': 'middle'}); t.textContent = `${pct} %`; svg.append(t);
 container.replaceChildren(svg);
}

// Ranking rows with thin gradient bars. rows: [{key, label, count}].
export function ranking(container, rows, opts = {}) {
 const max = rows.length ? rows[0].count : 0, total = opts.total || rows.reduce((a, b) => a + b.count, 0);
 const list = document.createElement('div'); list.className = 'ranking';
 rows.forEach(r => {
  const row = document.createElement('div'); row.className = 'rank-row';
  const head = document.createElement('div'); head.className = 'rank-head';
  const name = document.createElement('span'); name.className = 'rank-label'; name.textContent = r.label ? `${r.key} · ${r.label}` : r.key; name.title = name.textContent;
  const val = document.createElement('span'); val.className = 'rank-value'; val.textContent = `${fmt(r.count)} (${total ? Math.round(100 * r.count / total) : 0} %)`;
  head.append(name, val);
  if (opts.action) head.append(opts.action(r));
  const track = document.createElement('div'); track.className = 'rank-track';
  const fill = document.createElement('div'); fill.className = 'rank-fill'; fill.style.width = `${max ? Math.max(100 * r.count / max, 2) : 0}%`;
  track.append(fill); row.append(head, track);
  list.append(row);
 });
 if (!rows.length) { const p = document.createElement('p'); p.className = 'muted'; p.textContent = opts.empty || 'Nothing recorded in this window'; list.append(p); }
 container.replaceChildren(list);
}

// Tiny sparkline for the hero.
export function spark(container, values, color) {
 const W = 120, H = 28, max = Math.max(...values, 1);
 const svg = el('svg', {viewBox: `0 0 ${W} ${H}`, class: 'chart spark', 'aria-hidden': 'true'});
 const bw = W / values.length;
 values.forEach((v, i) => { const h = Math.max(H * v / max, 1); svg.append(el('rect', {x: i * bw + .5, y: H - h, width: Math.max(bw - 1, 1), height: h, fill: color, 'fill-opacity': v ? 1 : .45, rx: .5})); });
 container.replaceChildren(svg);
}
export { PALETTE, fmt };

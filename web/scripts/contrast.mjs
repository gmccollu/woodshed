// Checks WCAG 2.x contrast for the colour tokens in src/app.css, in light and dark mode.
// Glass backgrounds are translucent, so each background is composited over the page
// background the way it is stacked in the UI, using every gradient stop as the
// underlay and keeping the worst result. Exits 1 if any pair fails.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const css = readFileSync(fileURLToPath(new URL('../src/app.css', import.meta.url)), 'utf8');

function block(selector) {
  const start = css.indexOf(`${selector} {`);
  const body = css.slice(start, css.indexOf('\n}', start));
  const vars = {};
  for (const m of body.matchAll(/--([\w-]+):\s*([^;]+);/g)) vars[m[1]] = m[2].trim();
  return vars;
}

function parse(c) {
  c = c.trim();
  let m = c.match(/^#([0-9a-f]{6})$/i);
  if (m) {
    const n = parseInt(m[1], 16);
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
  }
  m = c.match(/^rgba?\(([^)]+)\)$/);
  if (m) {
    const p = m[1].split(',').map((s) => parseFloat(s));
    return [p[0], p[1], p[2], p[3] ?? 1];
  }
  throw new Error(`can't parse colour ${c}`);
}

const over = (top, under) => {
  const a = top[3];
  return [0, 1, 2].map((i) => top[i] * a + under[i] * (1 - a)).concat(1);
};

function lum([r, g, b]) {
  const f = (v) => {
    v /= 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}

const ratio = (a, b) => {
  const [l1, l2] = [lum(a), lum(b)].sort((x, y) => y - x);
  return (l1 + 0.05) / (l2 + 0.05);
};

// Background stacks, outermost first (after the page background).
const stacks = {
  page: [],
  shell: ['shell'],
  panel: ['shell', 'panel'],
  card: ['shell', 'panel', 'glass'],
  'card-strong': ['shell', 'panel', 'glass', 'glass-strong'],
  chip: ['chip'],
  input: ['shell', 'panel', 'glass', 'input'],
  'error-bg': ['error-bg'],
  'warn-bg': ['warn-bg'],
  'info-bg': ['info-bg'],
  btn: ['btn'],
  log: ['log-bg'],
  'log-bar': ['log-bar'],
  'ghost-on-log': ['log-bg', 'glass-strong'],
};

// [foreground var, stack names, minimum ratio]
const AA = 4.5;
const UI = 3; // non-text: status dots, input borders, focus ring
const pairs = [
  ['fg', ['page', 'panel', 'card', 'card-strong', 'chip', 'input', 'error-bg', 'warn-bg', 'info-bg'], AA],
  ['muted', ['page', 'panel', 'card', 'card-strong', 'chip', 'input'], AA],
  ['accent-fg', ['card', 'card-strong', 'warn-bg', 'chip'], AA],
  ['link', ['panel', 'card', 'card-strong', 'info-bg'], AA],
  ['ok-fg', ['panel', 'card', 'card-strong'], AA],
  ['warn-fg', ['card', 'card-strong', 'warn-bg'], AA],
  ['bad-fg', ['panel', 'card', 'card-strong', 'error-bg'], AA],
  ['fg', ['ghost-on-log'], AA],
  ['btn-fg', ['btn'], AA],
  ['log-fg', ['log', 'log-bar'], AA],
  ['log-dim', ['log', 'log-bar'], AA],
  ['log-host', ['log', 'log-bar'], AA],
  ['sev-emerg', ['log'], AA],
  ['sev-err', ['log'], AA],
  ['sev-warn', ['log'], AA],
  ['sev-notice', ['log'], AA],
  ['sev-info', ['log'], AA],
  ['sev-debug', ['log'], AA],
  ['sev-unknown', ['log'], AA],
  ['ok', ['card', 'card-strong'], UI],
  ['warn', ['card', 'card-strong'], UI],
  ['bad', ['card', 'card-strong'], UI],
  ['spark', ['card'], UI],
  ...[1, 2, 3, 4, 5, 6, 7, 8].map((i) => [`chart-${i}`, ['card', 'card-strong'], UI]),
  ['chart-mark', ['card', 'card-strong'], UI],
  ['input-border', ['card'], UI],
  ['link', ['card'], UI],
];

const light = block(':root');
const dark = { ...light, ...block('.dark') };
let failures = 0;
for (const [mode, vars] of [['light', light], ['dark', dark]]) {
  const get = (name) => {
    if (!(name in vars)) throw new Error(`missing --${name}`);
    return parse(vars[name]);
  };
  const underlays = ['bg', 'bg-warm', 'bg-cool', 'bg-green'].map(get);
  console.log(`\n${mode}`);
  for (const [fgName, stackNames, min] of pairs) {
    for (const s of stackNames) {
      let worst = Infinity;
      for (const base of underlays) {
        let bg = base;
        for (const layer of stacks[s]) bg = over(get(layer), bg);
        // Translucent foregrounds (input borders) are composited over their background too.
        const fg = over(get(fgName), bg);
        worst = Math.min(worst, ratio(fg, bg));
      }
      const ok = worst >= min;
      if (!ok) failures++;
      console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${fgName.padEnd(13)} on ${s.padEnd(11)} ${worst.toFixed(2)} (min ${min})`);
    }
  }
}
console.log(failures ? `\n${failures} pair(s) below WCAG AA` : '\nall pairs meet WCAG AA');
process.exit(failures ? 1 : 0);

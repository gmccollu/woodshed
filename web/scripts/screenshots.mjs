// Takes the review screenshots in web/screenshots/ from the mock-mode UI, in light
// and dark mode, by driving headless Chrome over the DevTools protocol (no extra
// npm packages). Start the mock server first:
//
//   npm run dev:mock            # serves http://127.0.0.1:5173
//   npm run screenshots         # all shots
//   npm run screenshots -- settings   # only shots whose name contains "settings"
//
// CHROME=/path/to/chrome, BASE=http://host:port and OUT=/some/dir override the defaults.
// Shots with a `check` also assert behaviour (a JS expression that must be true),
// and `noshot` entries are checks only, so this doubles as a UI smoke test. A `clip`
// (a CSS selector) captures just that element, wherever it is on the page.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const BASE = process.env.BASE ?? 'http://127.0.0.1:5173';
const OUT = process.env.OUT ?? fileURLToPath(new URL('../screenshots/', import.meta.url));
const PORT = 9300 + Math.floor(Math.random() * 500);
const W = 1400;
const H = 900;
const only = process.argv[2] ?? '';

// Helpers injected into the page for the interactive shots.
const H_JS = `
  window.__btn = (text) => [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
  window.__set = (el, v) => {
    const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  };
  window.__tick = () => new Promise((r) => setTimeout(r, 120));
  // Shows only the card with this id on the Settings page, so a long page's section fits one shot.
  window.__only = (id) => document.querySelectorAll('section.card').forEach((c) => { if (c.id !== id) c.style.display = 'none'; });
  window.__field = (label) => [...document.querySelectorAll('label')].find((l) => l.textContent.trim().startsWith(label))?.querySelector('input,textarea');
`;

const both = (s) => [
  { ...s, name: `${s.name}-light`, mode: 'light' },
  { ...s, name: `${s.name}-dark`, mode: 'dark' },
];

const SHOTS = [
  ...both({ name: 'welcome-waiting', url: '/?mock_panel=0&mock_firstrun=1&mock_firstmsg=0#/welcome', check: `document.body.innerText.includes('Waiting for the first message')` }),
  {
    name: 'welcome-received-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_firstrun=1&mock_firstmsg=1#/welcome',
    wait: 3500,
    check: `document.body.innerText.includes('First message received') && document.body.innerText.includes('From 127.0.0.1 at')
      && !!document.querySelector('a[href="#/dashboard"].pill-btn')`,
  },
  {
    name: 'welcome-names-first-not-latest',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_firstrun=1&mock_firstmsg=1#/welcome',
    wait: 12000,
    check: `document.body.innerText.includes('From 127.0.0.1 at')`,
  },
  {
    name: 'last-heard-reads-now',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    wait: 4500,
    check: `[...document.querySelectorAll('.strip .chip')].find((t) => t.textContent.includes('edge-fw-01'))?.title.includes('last heard now')`,
  },
  { name: 'first-run-redirect', noshot: true, mode: 'light', url: '/?mock_panel=0&mock_firstrun=1&mock_firstmsg=0', check: `location.hash === '#/welcome'` },
  ...both({ name: 'dashboard', url: '/?mock_panel=0#/dashboard', wait: 3000, check: `document.querySelectorAll('[role=log] .logline').length > 50 && document.body.innerText.includes(' rejected')` }),
  {
    name: 'dashboard-sampled-portclash-dark',
    mode: 'dark',
    url: '/?mock_panel=0&mock_rate=1284&mock_clash=1#/dashboard',
    wait: 3500,
    check: `document.body.innerText.includes('msg/s, showing a sample') && !!__btn('Retry')`,
  },
  {
    name: 'retry-clears-banner',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_clash=1#/dashboard',
    act: `__btn('Retry').click();`,
    after: 1500,
    check: `!document.body.innerText.includes('TCP 514 is in use')`,
  },
  {
    name: 'tail-keeps-1000-lines',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=5000#/dashboard',
    wait: 21000,
    check: `document.querySelectorAll('[role=log] .logline').length === 1000`,
  },
  {
    name: 'theme-remembered',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/about',
    act: `__btn('Dark').click();`,
    check: `localStorage.getItem('woodshed.theme') === 'dark' && document.documentElement.classList.contains('dark')`,
  },
  {
    name: 'settings-save-ok',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Keep logs for'), '14'); __btn('Save').click();`,
    after: 600,
    check: `document.body.innerText.includes('Saved.') && __field('Keep logs for').value === '14'`,
  },
  {
    name: 'filter-reaches-tail',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=200#/dashboard',
    act: `__set(document.querySelector('input[type=search]'), 'deny');`,
    after: 3000,
    check: `(() => { const l = [...document.querySelectorAll('[role=log] .logline')]; return l.length > 0 && l.every((x) => x.textContent.includes('deny')); })()`,
  },
  {
    name: 'allow-refused-sender',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `document.querySelector('[aria-label="Allow 198.51.100.7"]').click();`,
    after: 300,
    check: `document.querySelector('textarea').value.split('\\n').includes('198.51.100.7') && __btn('Added, save to apply')?.disabled`,
  },
  {
    name: 'ungrouped-tab-filters-tail',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=200#/dashboard',
    act: `__btn('Ungrouped').click();`,
    after: 3000,
    check: `(() => { const h = [...document.querySelectorAll('[role=log] .logline .c.h')]; return h.length > 0 && h.every((x) => x.textContent === '192.0.2.44'); })()`,
  },
  {
    name: 'rename-saves',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/devices',
    act: `document.querySelector('[aria-label="Rename edge-fw-01"]').click(); await new Promise(r => setTimeout(r, 200));
      const i = document.getElementById('edit-name-10.1.0.1'); __set(i, 'edge-fw-01a');
      i.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));`,
    after: 800,
    check: `document.body.innerText.includes('edge-fw-01a')`,
    report: `JSON.stringify({ err: [...document.querySelectorAll('[role=alert]')].map((x) => x.textContent), input: !!document.getElementById('edit-name-10.1.0.1'), rows: [...document.querySelectorAll('tbody tr')].slice(0, 3).map((r) => r.textContent.slice(0, 60)) })`,
  },
  {
    name: 'dashboard-group-paused-light',
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    wait: 2500,
    act: `__btn('HQ').click(); await new Promise(r => setTimeout(r, 1500)); __btn('Pause').click();`,
    after: 1500,
    check: `document.body.innerText.includes('Paused') && !!__btn('Resume')`,
  },
  ...both({ name: 'devices', url: '/?mock_panel=0#/devices' }),
  {
    name: 'devices-rename-dark',
    mode: 'dark',
    url: '/?mock_panel=0#/devices',
    act: `document.querySelector('[aria-label="Rename edge-fw-01"]').click();`,
  },
  {
    name: 'banners-writes-paused-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_clash=1&mock_paused=1#/devices',
  },
  ...both({ name: 'settings', url: '/?mock_panel=0#/settings' }),
  ...both({
    name: 'settings-errors',
    url: '/?mock_panel=0#/settings',
    act: `
      const ports = [...document.querySelectorAll('fieldset input[type=number]')];
      __set(ports[0], '70000');
      __set(document.querySelector('textarea'), '10.1.0.0/16\\n10.300.0.0/33');
      __set(__field('Offline after'), '2');
      __btn('Save').click();`,
    after: 800,
    check: `document.querySelectorAll('.ferr').length >= 3 && document.querySelectorAll('[aria-invalid=true]').length >= 3`,
  }),
  ...both({ name: 'about', url: '/?mock_panel=0#/about' }),
  { name: 'about-linux-light', mode: 'light', url: '/?mock_panel=0&mock_os=linux#/about' },
  // The UDP receive queue (SPEC §11.5): the banner while it overflows, and its hourly high-water view.
  ...both({
    name: 'banner-udp-queue-full',
    url: '/?mock_panel=0&mock_queue_full=1#/dashboard',
    wait: 1500,
    check: `[...document.querySelectorAll('.banner.warn')].some((b) => /UDP messages were dropped in the last hour because writing to disk fell behind \\(the queue holds 100,000\\)/.test(b.textContent)
      && !!b.querySelector('a[href="#/about"]')) && document.body.innerText.includes('because the UDP queue was full')`,
  }),
  ...both({
    name: 'about-udp-queue-full',
    url: '/?mock_panel=0&mock_queue_full=1&mock_uptime_hours=30#/about',
    wait: 1500,
    check: `document.body.innerText.includes('UDP receive queue') && document.querySelectorAll('.plot .col').length === 24
      && document.querySelectorAll('.plot .bar.warn').length >= 1 && document.body.innerText.includes('UDP queue full')`,
  }),
  {
    name: 'about-udp-queue-calm-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_uptime_hours=30#/about',
    wait: 1500,
    check: `document.body.innerText.includes('Most at once, 24 h') && document.querySelectorAll('.plot .bar.warn').length === 0
      && document.body.innerText.includes('lost before Woodshed read them')
      && ![...document.querySelectorAll('.banner')].some((b) => b.textContent.includes('UDP messages were dropped'))`,
  },
  // ---- Dashboard layout, wrap, severity chips ----
  { name: 'dashboard-2000-light', mode: 'light', w: 2000, h: 1100, url: '/?mock_panel=0#/dashboard', wait: 3000 },
  { name: 'dashboard-2000-dark', mode: 'dark', w: 2000, h: 1100, url: '/?mock_panel=0#/dashboard', wait: 3000 },
  {
    name: 'tail-nowrap-one-line-per-message',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    wait: 2500,
    check: `(() => { const l = [...document.querySelectorAll('[role=log] .logline')]; return l.length > 50 && l.every((x) => x.offsetHeight <= 24)
      && getComputedStyle(l[0]).whiteSpace === 'pre'; })()`,
  },
  {
    name: 'dashboard-wrap-on-light',
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    act: `__btn('Raw').click(); await __tick(); __btn('Wrap').click();`,
    after: 800,
    check: `[...document.querySelectorAll('[role=log] .logline')].some((x) => x.offsetHeight > 30)`,
  },
  {
    name: 'tail-debug-only-light',
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    act: `window.__woodshedMock.livePaths.length = 0;
      document.querySelector('[aria-label="Live tail severities"] button[title^="Debug"]').dispatchEvent(new MouseEvent('click', { bubbles: true, altKey: true }));`,
    after: 2500,
    check: `(() => { const p = window.__woodshedMock.livePaths; const s = [...document.querySelectorAll('[role=log] .logline .c.s')];
      return p.length > 0 && /[?&]severities=7(&|$)/.test(p[p.length - 1]) && s.length > 0 && s.every((x) => x.textContent === 'debug'); })()`,
  },
  {
    name: 'chip-filters-tail',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    act: `[...document.querySelectorAll('.strip .chip')].find((c) => c.textContent.includes('edge-fw-02')).click();
      await new Promise((r) => setTimeout(r, 2000));
      const one = [...document.querySelectorAll('[role=log] .logline .c.h')].map((x) => x.textContent);
      if (!one.length || one.some((h) => h !== 'edge-fw-02')) throw new Error('single chip did not filter: ' + [...new Set(one)]);
      [...document.querySelectorAll('.strip .chip')].find((c) => c.textContent.includes('core-sw-01')).dispatchEvent(new MouseEvent('click', { bubbles: true, ctrlKey: true }));`,
    after: 2500,
    check: `(() => { const h = new Set([...document.querySelectorAll('[role=log] .logline .c.h')].map((x) => x.textContent));
      return h.size === 2 && h.has('edge-fw-02') && h.has('core-sw-01'); })()`,
  },
  // ---- Embedded line breaks: one message is one row with Wrap off ----
  {
    name: 'tail-embedded-break-one-row',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    // The message is rare in the random traffic: the mock sends a few on demand.
    act: `__set(document.querySelector('input[type=search]'), 'future version'); await __tick();
      if (__woodshedMock.emit('leading-break', 3) !== 3) throw new Error('mock sent no leading-break lines');`,
    after: 1500,
    check: `(() => { const l = [...document.querySelectorAll('[role=log] .logline')];
      return l.length >= 3 && l.every((x) => x.offsetHeight <= 24 && x.querySelector('.m').textContent.includes('↵') && !x.querySelector('.m').textContent.includes('\\n')); })()`,
  },
  {
    name: 'tail-embedded-break-raw-light',
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    // The message is rare in the random traffic: the mock sends a few on demand.
    act: `__set(document.querySelector('input[type=search]'), 'job finished'); await __tick(); __btn('Raw').click();
      if (__woodshedMock.emit('embedded-break', 3) !== 3) throw new Error('mock sent no embedded-break lines');`,
    after: 1500,
    check: `(() => { const l = [...document.querySelectorAll('[role=log] .logline')];
      return l.length >= 3 && l.every((x) => x.offsetHeight <= 24 && x.textContent.includes('\\\\r\\\\n')); })()`,
    report: `JSON.stringify([...document.querySelectorAll('[role=log] .logline')].slice(0, 6).map((x) => [x.offsetHeight, x.textContent.slice(0, 140)]))`,
  },
  {
    name: 'search-embedded-break-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=future%20version&r=24h',
    wait: 2500,
    check: `(() => { const l = [...document.querySelectorAll('.logline.clickable')];
      return l.length > 20 && l.every((x) => x.offsetHeight <= 24 && x.textContent.includes('↵')) && document.querySelectorAll('mark.hl').length >= l.length; })()`,
  },
  {
    name: 'context-embedded-break-one-row',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=future%20version&r=24h',
    wait: 2500,
    act: `document.querySelectorAll('.logline.clickable')[30].click();`,
    after: 1500,
    check: `(() => { const l = [...document.querySelectorAll('[role=dialog] .logline')]; const hit = document.querySelector('[role=dialog] .logline.hit');
      return l.length > 50 && hit && hit.textContent.includes('↵') && l.every((x) => x.offsetHeight <= 24); })()`,
  },
  {
    name: 'tail-fullscreen-dark',
    mode: 'dark',
    url: '/?mock_panel=0#/dashboard',
    act: `__btn('Full screen').click();`,
    check: `document.querySelector('.tail.full')?.getBoundingClientRect().width === innerWidth`,
  },

  // ---- Scale: 10,000 devices, paginated ----
  {
    name: 'devices-10k-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_devices=10000#/devices',
    wait: 3000,
    check: `/1–200 of [\\d,]{5,}/.test(document.body.innerText) && document.querySelectorAll('tbody tr').length === 200`,
  },
  {
    name: 'devices-10k-next-and-search',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_devices=10000#/devices',
    wait: 2500,
    act: `__btn('Next →').click(); await new Promise((r) => setTimeout(r, 1500));
      if (!/201–400 of/.test(document.body.innerText)) throw new Error('next page not shown');
      __set(document.querySelector('input[type=search]'), 'sw-0004');`,
    after: 2500,
    check: `(() => { const rows = [...document.querySelectorAll('tbody tr')]; return rows.length > 0 && rows.length <= 200
      && rows.every((r) => r.textContent.includes('sw-0004')) && /1–\\d+ of \\d+ matching/.test(document.body.innerText); })()`,
  },
  {
    name: 'dashboard-10k-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_devices=10000#/dashboard',
    wait: 3000,
    check: `document.querySelectorAll('.strip button.chip').length === 30 && /All [\\d,]{5,} devices/.test(document.querySelector('.strip .more')?.textContent ?? '')`,
  },
  {
    name: 'banner-device-limit-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_device_limit=1#/dashboard',
    wait: 2000,
    check: `document.body.innerText.includes('New senders are being refused') && !!document.querySelector('a[href="#/settings?section=limits"]')`,
  },
  {
    name: 'device-limit-link-opens-sender-limits',
    noshot: true,
    report: `JSON.stringify({ top: document.getElementById('sender-limits')?.getBoundingClientRect().top, y: scrollY, h: innerHeight, hash: location.hash })`,
    mode: 'light',
    url: '/?mock_panel=0&mock_device_limit=1#/dashboard',
    wait: 2000,
    act: `document.querySelector('a[href="#/settings?section=limits"]').click();`,
    after: 1500,
    check: `(() => { const el = document.getElementById('sender-limits'); const r = el?.getBoundingClientRect(); return !!r && r.top >= 0 && r.top < innerHeight; })()`,
  },
  {
    name: 'sender-limits-validation',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Active devices'), '0'); __btn('Save').click();`,
    after: 800,
    check: `document.getElementById('err-listeners.max_devices')?.textContent.startsWith('Use a whole number')`,
  },
  {
    name: 'require-login-local',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_password=1#/settings',
    act: `const box = __field('Require login on this machine too'); if (box.disabled) throw new Error('disabled with a password set');
      box.click(); await __tick(); __btn('Save').click(); await new Promise((r) => setTimeout(r, 1500));
      if (!__field('Password')) throw new Error('no login form after turning on require_login_local');
      __set(__field('Password'), 'woodshed-demo'); await __tick(); __btn('Log in').click();`,
    after: 1500,
    check: `location.hash.startsWith('#/settings') && __field('Require login on this machine too').checked && !!__btn('Log out')`,
  },
  {
    name: 'require-login-local-needs-password',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    check: `__field('Require login on this machine too').disabled && document.body.innerText.includes('shared or multi-user machines')`,
  },
  {
    name: 'password-change-needs-current-localhost',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_password=1#/settings',
    check: `!!__field('Current password') && document.body.innerText.includes('Change password')`,
  },
  {
    name: 'refused-sender-reasons',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    check: `(() => { const rows = [...document.querySelectorAll('tr')]; const ps = rows.find((r) => r.textContent.includes('10.9.0.66'));
      const al = rows.find((r) => r.textContent.includes('198.51.100.7'));
      return ps && al && ps.textContent.includes('too many TCP connections') && !ps.querySelector('button')
        && al.textContent.includes('not on the allowlist') && !!al.querySelector('button'); })()`,
  },

  // ---- Hostile content: long lines, spoofing characters ----
  {
    name: 'search-long-line-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=payload%20dump&r=7d',
    wait: 2500,
    check: `(() => { const l = [...document.querySelectorAll('.logline.clickable')]; return l.length > 0
      && l.every((x) => x.offsetHeight <= 24 && x.textContent.length < 9000 && x.textContent.includes('show full message')); })()`,
  },
  {
    name: 'long-line-expands-in-place',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=payload%20dump&r=7d',
    wait: 2500,
    act: `document.querySelector('.logline.clickable .more-btn').click();`,
    after: 600,
    check: `document.querySelector('.logline.clickable').textContent.length > 20000 && !document.querySelector('[role=dialog]')`,
  },
  {
    name: 'search-spoofing-chars-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=file%20uploaded&r=24h',
    wait: 2500,
    check: `(() => { const l = [...document.querySelectorAll('.logline.clickable .m')]; return l.length > 0
      && l.every((x) => x.textContent.includes('⟨U+202E⟩') && x.textContent.includes('⟨U+200B⟩')
        && !x.textContent.includes('\u202e') && !x.textContent.includes('\u200b')); })()`,
  },
  {
    name: 'spoofing-chars-raw-escaped',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=file%20uploaded&r=24h',
    wait: 2500,
    act: `__btn('Raw').click();`,
    after: 500,
    check: `(() => { const l = [...document.querySelectorAll('.logline.clickable .m')]; return l.length > 0
      && l.every((x) => x.textContent.includes('\\\\u202e') && !x.textContent.includes('\u202e')); })()`,
  },

  // ---- Recovering from a bad save; dismissing banners; another Woodshed on the port ----
  {
    name: 'settings-undo-after-bad-save-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_service_514=1#/settings',
    act: `const ports = [...document.querySelectorAll('fieldset input[type=number]')];
      if (ports[0].value !== '15514' || ports[1].value !== '15514') throw new Error('expected 15514 to start with');
      if (!__btn('Discard changes').disabled) throw new Error('Discard changes enabled with no edits');
      __set(ports[0], '514'); __set(ports[1], '514'); await __tick();
      if (__btn('Discard changes').disabled) throw new Error('Discard changes disabled after an edit');
      __btn('Save').click();
      await new Promise((r) => setTimeout(r, 2500));
      if (!document.body.innerText.includes('Your last save stopped a listener')) throw new Error('no undo notice');`,
    after: 300,
    check: `[...document.querySelectorAll('button')].filter((b) => b.textContent.trim() === 'Undo last save').length === 2`,
  },
  {
    name: 'undo-last-save-restores-ports',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_service_514=1#/settings',
    act: `const ports = [...document.querySelectorAll('fieldset input[type=number]')];
      __set(ports[0], '514'); __set(ports[1], '514'); await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 2500));
      document.querySelector('.banner .pill-btn').click();`,
    after: 2000,
    check: `(() => { const ports = [...document.querySelectorAll('fieldset input[type=number]')];
      return ports[0].value === '15514' && ports[1].value === '15514' && !document.body.innerText.includes('in use by another Woodshed')
        && !document.body.innerText.includes('Your last save stopped a listener') && !sessionStorage.getItem('woodshed.undo'); })()`,
  },
  {
    name: 'banner-woodshed-service-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_service_514=1&mock_listen_514=1#/dashboard',
    check: `(() => { const h = [...document.querySelectorAll('[data-holder]')];
      return h.length === 1 && h[0].textContent.trim().startsWith("Another copy of Woodshed is using port 514: the installed service. This copy can't receive logs; stop it, or use the service's page.")
        && h[0].querySelector('a')?.getAttribute('href') === 'http://localhost:8514/'; })()`,
  },
  {
    name: 'banner-ui-port-busy',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_ui_port_busy=1#/dashboard',
    check: `(() => { const b = [...document.querySelectorAll('.banner.warn')].find((x) => x.textContent.includes("can't open its web page"));
      return !!b && !!b.querySelector('[aria-label="Hide this alert"]'); })()`,
  },
  {
    name: 'dismissed-banner-stays-hidden-then-returns-on-change',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_device_limit=1#/dashboard',
    act: `const b = [...document.querySelectorAll('.banner')].find((x) => x.textContent.includes('New senders are being refused'));
      b.querySelector('[aria-label="Hide this alert"]').click(); await __tick();
      if (document.body.innerText.includes('New senders are being refused')) throw new Error('not hidden');
      if (!__btn('1 hidden alert')) throw new Error('no hidden-alert pill');
      location.hash = '#/devices'; await new Promise((r) => setTimeout(r, 1500));
      if (document.body.innerText.includes('New senders are being refused')) throw new Error('back after navigation');
      window.__woodshedMock.bannerNote = ' Updated.';
      await new Promise((r) => setTimeout(r, 6000));`,
    after: 200,
    check: `document.body.innerText.includes('Their messages count as dropped. Updated.') && !__btn('1 hidden alert')`,
  },
  {
    name: 'hidden-alert-pill-brings-it-back',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_device_limit=1#/dashboard',
    act: `document.querySelector('.banner [aria-label="Hide this alert"]').click(); await __tick(); __btn('1 hidden alert').click();`,
    after: 300,
    check: `document.body.innerText.includes('New senders are being refused') && !__btn('1 hidden alert')`,
  },
  {
    name: 'dismissed-error-not-kept-past-reload',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_clash=1#/dashboard',
    act: `document.querySelector('.banner.error [aria-label="Hide this alert"]').click(); await __tick();`,
    after: 300,
    check: `!document.body.innerText.includes('TCP 514 is in use') && !(sessionStorage.getItem('woodshed.dismissed') ?? '').includes('listener_bind')`,
  },

  // ---- Blocking a sender ----
  {
    name: 'block-from-dashboard-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=120#/dashboard',
    wait: 2500,
    act: `document.querySelector('[aria-label="More for edge-fw-02"]').click(); await __tick();
      [...document.querySelectorAll('[role=menuitem]')].find((b) => b.textContent.startsWith('Block this sender')).click(); await __tick();
      const dlg = document.querySelector('[role=alertdialog]');
      if (!dlg || !dlg.textContent.includes('Block 10.1.0.2 (edge-fw-02)?') || !dlg.textContent.includes("Woodshed will refuse and count its messages. Its existing logs stay searchable.")) throw new Error('no confirmation');
      [...dlg.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Block').click();
      await new Promise((r) => setTimeout(r, 1500));
      window.__n0 = [...document.querySelectorAll('[role=log] .logline .c.h')].filter((h) => h.textContent === 'edge-fw-02').length;
      await new Promise((r) => setTimeout(r, 3000));`,
    after: 100,
    check: `(() => { const n1 = [...document.querySelectorAll('[role=log] .logline .c.h')].filter((h) => h.textContent === 'edge-fw-02').length;
      return n1 === window.__n0 && ![...document.querySelectorAll('.strip .chip')].some((c) => c.textContent.includes('edge-fw-02'))
        && document.body.innerText.includes('Blocked 10.1.0.2 (edge-fw-02).') && !!__btn('Undo') && /Show blocked \\(1\\)/.test(document.body.innerText); })()`,
  },
  {
    name: 'block-undo-restores-chip',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    wait: 2000,
    act: `document.querySelector('[aria-label="More for edge-fw-02"]').click(); await __tick();
      [...document.querySelectorAll('[role=menuitem]')].find((b) => b.textContent.startsWith('Block this sender')).click(); await __tick();
      [...document.querySelector('[role=alertdialog]').querySelectorAll('button')].find((b) => b.textContent.trim() === 'Block').click();
      await new Promise((r) => setTimeout(r, 1200));
      __btn('Undo').click();`,
    after: 1500,
    check: `[...document.querySelectorAll('.strip .chip')].some((c) => c.textContent.includes('edge-fw-02')) && !/Show blocked/.test(document.body.innerText)`,
  },
  {
    name: 'block-from-tail-line-menu',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    wait: 2500,
    act: `const line = [...document.querySelectorAll('[role=log] .logline')].find((l) => l.querySelector('.c.h').textContent === 'edge-fw-01');
      line.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, clientX: 400, clientY: 400 })); await __tick();`,
    after: 300,
    check: `[...document.querySelectorAll('[role=menuitem]')].some((b) => b.textContent.startsWith('Block this sender')) && document.querySelector('[role=menu]').textContent.includes('10.1.0.1 (edge-fw-01)')`,
  },
  {
    name: 'devices-blocked-filter-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_blocked=10.1.0.2/32,10.8.0.1#/devices',
    wait: 1500,
    act: `[...document.querySelectorAll('[role=radio]')].find((b) => b.textContent === 'Blocked').click();`,
    after: 1500,
    check: `(() => { const rows = [...document.querySelectorAll('tbody tr')]; return rows.length === 2
      && rows.every((r) => r.textContent.includes('Blocked') && !!r.querySelector('button') && [...r.querySelectorAll('button')].some((b) => b.textContent.trim() === 'Unblock')); })()`,
  },
  {
    name: 'unblock-still-covered-by-cidr',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_blocked=10.1.0.2/32,10.1.0.0/30#/devices',
    wait: 1500,
    act: `[...document.querySelectorAll('[role=radio]')].find((b) => b.textContent === 'Blocked').click(); await new Promise((r) => setTimeout(r, 1200));
      const row = [...document.querySelectorAll('tbody tr')].find((r) => r.textContent.includes('edge-fw-02'));
      [...row.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Unblock').click();`,
    after: 1200,
    check: `document.body.innerText.includes('Still blocked by 10.1.0.0/30 in Settings → Blocklist.')
      && document.querySelector('a[href="#/settings?section=blocklist"]')?.textContent === 'Open the blocklist'
      && [...document.querySelectorAll('tbody tr')].some((r) => r.textContent.includes('edge-fw-02'))`,
  },
  {
    name: 'settings-blocklist-round-trip',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `const t = __field('Blocklist');
      __set(t, '203.0.113.0/24' + String.fromCharCode(10) + '10.1.0.300'); await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 800));
      const e = document.getElementById('err-listeners.blocklist');
      if (!e || !e.textContent.includes('Entry 2 (10.1.0.300)')) throw new Error('no blocklist entry error: ' + (e && e.textContent));
      __set(t, '203.0.113.0/24' + String.fromCharCode(10) + '10.1.0.2'); await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 800));
      location.hash = '#/about'; await new Promise((r) => setTimeout(r, 500)); location.hash = '#/settings';`,
    after: 1500,
    check: `__field('Blocklist').value === '203.0.113.0/24' + String.fromCharCode(10) + '10.1.0.2'`,
  },
  // ---- rc5: settings ETag (If-Match, 409), the new UI-access lists, the restarting flag ----
  {
    name: 'settings-saves-send-if-match',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Keep logs for'), '14'); await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 700));
      window.__first = __woodshedMock.lastIfMatch;
      __set(__field('Keep logs for'), '15'); await __tick(); __btn('Save').click();`,
    after: 700,
    check: `document.body.innerText.includes('Saved.') && !document.querySelector('.conflict') && /^"s\\d+"$/.test(window.__first)
      && /^"s\\d+"$/.test(__woodshedMock.lastIfMatch) && window.__first !== __woodshedMock.lastIfMatch`,
  },
  {
    name: 'settings-saves-without-put-etag',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_put_no_etag=1#/settings',
    act: `__set(__field('Keep logs for'), '14'); await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 900));
      __set(__field('Keep logs for'), '15'); await __tick(); __btn('Save').click();`,
    after: 900,
    check: `document.body.innerText.includes('Saved.') && !document.querySelector('.conflict') && __field('Keep logs for').value === '15'`,
  },
  {
    name: 'settings-conflict-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Keep logs for'), '21'); __set(__field('Trusted host names'), 'logs.example.net:443'); await __tick();
      window.__stale = __woodshedMock.lastIfMatch;
      __woodshedMock.changeSettingsElsewhere(); __btn('Save').click();`,
    after: 700,
    check: `(() => { const c = document.querySelector('.conflict[role=alert]');
      return !!c && c.textContent.includes('Settings changed elsewhere since you opened this page') && !!__btn('Reload')
        && __field('Keep logs for').value === '21' && __field('Trusted host names').value === 'logs.example.net:443'
        && c.textContent.includes('Keep logs for (days): yours 21') && c.textContent.includes('Trusted host names: yours logs.example.net:443')
        && !document.body.innerText.includes('Saved.'); })()`,
  },
  {
    name: 'settings-conflict-reloaded-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Keep logs for'), '21'); await __tick();
      __woodshedMock.changeSettingsElsewhere(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 700)); __btn('Reload').click();`,
    after: 700,
    check: `(() => { const c = document.querySelector('.conflict');
      return !!c && __field('Keep logs for').value === '45' && c.textContent.includes('yours 21, now 45') && !__btn('Reload') && !!__btn('Done'); })()`,
  },
  {
    name: 'settings-conflict-redo-saves',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Keep logs for'), '21'); await __tick();
      __woodshedMock.changeSettingsElsewhere(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 700)); __btn('Reload').click();
      await new Promise((r) => setTimeout(r, 700));
      __set(__field('Keep logs for'), '21'); await __tick(); __btn('Save').click();`,
    after: 800,
    check: `document.body.innerText.includes('Saved.') && !document.querySelector('.conflict') && __field('Keep logs for').value === '21'`,
  },
  {
    name: 'block-then-stale-settings-save',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    // Blocking a device (from another tab) changes the blocklist, so this page's ETag is stale.
    act: `window.__blockStatus = await __woodshedMock.request('PATCH', '/api/devices/10.1.0.2', { blocked: true });
      __set(__field('Keep logs for'), '22'); await __tick(); __btn('Save').click();`,
    after: 700,
    check: `window.__blockStatus === 200 && !!document.querySelector('.conflict') && __field('Keep logs for').value === '22'`,
  },
  {
    name: 'settings-hostnames-errors-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `const nl = String.fromCharCode(10);
      __set(__field('Extra certificate names'), 'logs.example.net' + nl + 'https://syslog.example.net');
      __set(__field('Trusted host names'), 'proxy.example.net:443' + nl + 'proxy.example.net:99999');
      await __tick(); __btn('Save').click();`,
    after: 800,
    check: `document.getElementById('err-ui.extra_hostnames')?.textContent.includes('Entry 2 (https://syslog.example.net)')
      && document.getElementById('err-ui.trusted_hosts')?.textContent.includes('Entry 2 (proxy.example.net:99999)')
      && document.querySelectorAll('textarea[aria-invalid=true]').length === 2`,
  },
  {
    name: 'settings-hostnames-round-trip',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `const nl = String.fromCharCode(10);
      __set(__field('Extra certificate names'), 'logs.example.net' + nl + '10.1.0.50');
      __set(__field('Trusted host names'), 'proxy.example.net:443, [fd00::50]:8514');
      await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 800));
      location.hash = '#/about'; await new Promise((r) => setTimeout(r, 500)); location.hash = '#/settings';`,
    after: 1500,
    check: `__field('Extra certificate names').value === 'logs.example.net' + String.fromCharCode(10) + '10.1.0.50'
      && __field('Trusted host names').value === 'proxy.example.net:443' + String.fromCharCode(10) + '[fd00::50]:8514'`,
  },
  {
    name: 'settings-new-cert-name-note-lan',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1&mock_loggedin=1#/settings',
    act: `__set(__field('Extra certificate names'), 'logs.example.net');`,
    after: 300,
    check: `document.body.innerText.includes('the certificate is regenerated: browsers warn once more, and the fingerprint changes')`,
  },
  {
    name: 'settings-restarting-flag-shows-new-address',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('UI port'), '8600'); await __tick(); __btn('Save').click();`,
    after: 800,
    check: `document.body.innerText.includes('restarting its web UI at a new address') && document.body.innerText.includes('http://localhost:8600/')`,
  },
  {
    name: 'settings-no-restart-no-notice',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `__set(__field('Trusted host names'), 'logs.example.net'); await __tick(); __btn('Save').click();`,
    after: 800,
    check: `document.body.innerText.includes('Saved.') && !document.querySelector('.moved')`,
  },
  {
    name: 'banner-udp-buffer-small-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_os=linux&mock_small_buffer=1#/dashboard',
    wait: 1500,
    check: `(() => { const b = [...document.querySelectorAll('.banner.warn')].find((x) => x.textContent.includes('208 KiB receive buffer'));
      const a = b?.querySelector('a[href="https://github.com/gmccollu/woodshed/blob/main/docs/install.md#containers-lxc-docker-kubernetes"]');
      return !!a && a.target === '_blank' && a.rel.includes('noopener') && a.textContent.includes('Containers') && !!b.querySelector('[aria-label="Hide this alert"]'); })()`,
  },
  {
    name: 'refused-blocked-sender-unblock',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_blocked=10.1.0.2/32#/settings',
    wait: 4000,
    act: `const row = [...document.querySelectorAll('tr')].find((r) => r.textContent.includes('10.1.0.2') && r.textContent.includes('blocked'));
      if (!row) throw new Error('no blocked refusal row');
      row.querySelector('[aria-label="Unblock 10.1.0.2"]').click();`,
    after: 300,
    check: `!__field('Blocklist').value.includes('10.1.0.2')`,
  },

  // ---- Custom time range (Export and Search), 1400 and 900 px ----
  ...[1400, 900].flatMap((w) =>
    ['export', 'events'].flatMap((page) =>
      both({
        name: `${page}-custom-range-${w}`,
        w,
        url: page === 'export' ? '/?mock_panel=0#/export' : '/?mock_panel=0#/events?q=deny&r=24h',
        wait: 1800,
        act: `__btn('Custom').click(); await __tick();`,
        after: 400,
        check: `(() => {
          const ins = [...document.querySelectorAll('.custom input')];
          if (ins.length !== 4) return false;
          const [fd, ft, td, tt] = ins.map((i) => i.getBoundingClientRect());
          const sameRow = (a, b) => Math.abs(a.top - b.top) < 4;
          // Wide: From and To on one line. Narrow: To below From. Never a time input wrapped away from its date.
          const ok = sameRow(fd, ft) && sameRow(td, tt);
          const readout = document.querySelector('.custom .readout').textContent.trim();
          return ok && ins.every((i) => Math.abs(i.getBoundingClientRect().height - 36) < 1) && /^covers /.test(readout); })()`,
      }),
    ),
  ),
  {
    name: 'custom-range-from-after-to',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/export',
    wait: 1500,
    act: `__btn('Custom').click(); await __tick();
      const [fd] = document.querySelectorAll('.custom input');
      const later = new Date(Date.now() + 2 * 86400000);
      const v = later.getFullYear() + '-' + String(later.getMonth() + 1).padStart(2, '0') + '-' + String(later.getDate()).padStart(2, '0');
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(fd, v);
      fd.dispatchEvent(new Event('change', { bubbles: true }));`,
    after: 400,
    check: `document.querySelector('.tr .ferr')?.textContent === '"From" must be before "To".' && document.querySelector('.custom input').getAttribute('aria-invalid') === 'true'`,
  },

  // ---- Retention estimate ----
  {
    name: 'disk-estimate-and-cap-banner-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=1284#/dashboard',
    wait: 2000,
    check: `(() => { const e = document.querySelector('.est'); return !!e && e.textContent.includes('≈ 13 days of history at the current rate')
      && e.textContent.includes('limited by the size cap')
      && e.title.startsWith('Estimated from the last 24 h of intake') && e.title.includes("compression measured on this machine's closed files (9.2×)")
      && [...document.querySelectorAll('.banner.warn')].some((b) => b.textContent.includes('cap keeps about 13 days') && !!b.querySelector('a[href="#/settings?section=storage"]')); })()`,
  },
  {
    name: 'disk-estimate-age-limited',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    wait: 2000,
    check: `(() => { const e = document.querySelector('.est'); return !!e && /≈ \\d+ days of history at the current rate/.test(e.textContent) && !e.textContent.includes('limited by')
      && !document.body.innerText.includes('cap keeps about'); })()`,
  },
  {
    name: 'settings-estimate-preview-while-typing-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=1284#/settings?section=storage',
    wait: 1500,
    act: `const cap = __field('Disk cap (GiB)');
      __set(cap, '10'); await new Promise((r) => setTimeout(r, 900));
      window.__p1 = document.querySelector('[data-estimate]').textContent.replace(/\\s+/g, ' ').trim();
      __set(cap, '40'); await new Promise((r) => setTimeout(r, 900));`,
    after: 100,
    check: `(() => { const p2 = document.querySelector('[data-estimate]').textContent.replace(/\\s+/g, ' ').trim();
      return window.__p1.startsWith('10 GiB ≈ 6.4 days at the current rate (≈ 1.6 GiB/day).') && window.__p1.includes('The size cap is reached first')
        && p2.startsWith('40 GiB ≈ 25 days at the current rate') && document.querySelectorAll('table.ex tbody tr').length === 3; })()`,
  },

  // ---- Search ----
  ...both({
    name: 'search-results',
    url: '/?mock_panel=0#/events?q=deny&r=24h',
    wait: 3000,
    check: `document.querySelectorAll('.logline.clickable').length === 500 && document.querySelectorAll('mark.hl').length > 100`,
  }),
  {
    name: 'search-partial-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_slow_scan=1#/events?q=failover&r=7d',
    wait: 2600,
    check: `/Scanned [\\d.]+ \\w+ in [\\d,]+ files…/.test(document.body.innerText) && !!__btn('Cancel')`,
  },
  {
    name: 'search-context-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny&r=24h',
    wait: 2500,
    act: `document.querySelectorAll('.logline.clickable')[60].click();`,
    after: 1500,
    check: `(() => { const n = document.querySelectorAll('[role=dialog] .logline').length;
      const atEnd = document.querySelector('[role=dialog]').innerText.includes('Newest stored line');
      return !!document.querySelector('[role=dialog] .logline.hit mark.hl') && n >= 51 && (n === 101 || atEnd); })()`,
  },
  {
    name: 'search-regex-error-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny%20(tcp&re=1&r=1h',
    wait: 1500,
    check: `document.querySelector('#sq-err')?.textContent.startsWith('error parsing regexp') && document.querySelector('#sq').getAttribute('aria-invalid') === 'true'`,
  },
  {
    name: 'search-pagination-no-duplicates',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=24h',
    wait: 2500,
    act: `__btn('Load 500 more').click(); await new Promise((r) => setTimeout(r, 2500)); __btn('Load 500 more').click();`,
    after: 2500,
    check: `(() => { const refs = [...document.querySelectorAll('.logline.clickable')].map((x) => x.dataset.ref); return refs.length === 1500 && new Set(refs).size === 1500; })()`,
  },
  {
    name: 'search-partial-finishes-and-cancels',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_slow_scan=1#/events?q=failover&r=24h',
    wait: 1800,
    act: `__btn('Cancel').click();`,
    after: 400,
    check: `!__btn('Cancel') && (!!__btn('Continue the scan') || document.body.innerText.includes('Cancelled before anything matched'))`,
  },
  {
    name: 'search-empty-state',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=no-such-text-anywhere&r=15m',
    wait: 1500,
    check: `document.body.innerText.includes('No matches in this range')`,
  },
  {
    name: 'search-export-these-results',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny&r=1h&group=HQ',
    wait: 2000,
    act: `__btn('Export these results').click();`,
    after: 1500,
    check: `location.hash.startsWith('#/export?') && document.querySelector('#exq').value === 'deny'
      && document.body.innerText.includes('Filled in from Events') && document.body.innerText.includes('Group: HQ')`,
  },
  {
    name: 'search-export-keeps-regex-and-case',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny%20(tcp%7Cudp)&re=1&cs=1&r=1h',
    wait: 2000,
    act: `if (__btn('Export these results').disabled) throw new Error('export disabled for a regex search'); __btn('Export these results').click();`,
    after: 1500,
    check: `document.querySelector('#exq').value === 'deny (tcp|udp)' && __btn('Regex').getAttribute('aria-pressed') === 'true'
      && __btn('Aa Case').getAttribute('aria-pressed') === 'true' && /Up to [\\d,]+ lines/.test(document.body.innerText)`,
  },
  {
    name: 'search-none-selected',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h&sev=none',
    wait: 1500,
    check: `document.querySelectorAll('.logline.clickable').length === 0 && document.body.innerText.includes('No levels selected')`,
  },
  {
    name: 'tail-none-sends-none',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/dashboard',
    act: `window.__woodshedMock.livePaths.length = 0; __btn('None').click();`,
    after: 1500,
    check: `(() => { const p = window.__woodshedMock.livePaths; return p.length > 0 && /[?&]severities=none(&|$)/.test(p[p.length - 1])
      && document.querySelectorAll('[role=log] .logline').length === 0 && document.body.innerText.includes('No levels selected'); })()`,
  },


  // ---- Events: browse, program/tag, host and exclude, clickable columns, the old #/search link ----
  {
    name: 'events-browse-by-default',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events',
    wait: 2500,
    check: `document.querySelectorAll('.logline.clickable').length === 500 && document.querySelector('#sq').placeholder === 'Browse every stored message; type to filter'
      && document.querySelector('h1').textContent === 'Events' && document.title.startsWith('Events')
      && document.querySelector('nav a[aria-current=page]').textContent.trim() === 'Events' && location.hash.startsWith('#/events?')`,
  },
  {
    name: 'search-link-still-works',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/search?q=deny&r=24h',
    wait: 2500,
    check: `document.querySelectorAll('.logline.clickable').length === 500 && document.querySelector('#sq').value === 'deny'
      && document.querySelector('nav a[aria-current=page]').textContent.trim() === 'Events'`,
  },
  ...both({
    name: 'events-fields',
    url: '/?mock_panel=0#/events?r=24h&app=%25FW-*&host=edge-fw-01&ex=denied',
    wait: 3000,
    check: `(() => { const rows = [...document.querySelectorAll('.logline.clickable')];
      return rows.length > 50 && rows.every((r) => r.querySelector('.c.ap').textContent.startsWith('%FW-6-') && r.querySelector('.c.hn').textContent === 'edge-fw-01')
        && !rows.some((r) => r.textContent.includes('denied')) && !!document.querySelector('.logline.colhead'); })()`,
  }),
  {
    name: 'events-click-host-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=session&r=24h',
    wait: 2500,
    act: `window.__before = document.querySelectorAll('.logline.clickable').length;
      const b = [...document.querySelectorAll('.logline.clickable .c.hn.cell')].find((x) => x.textContent === 'edge-fw-02');
      if (!b) throw new Error('no edge-fw-02 host cell'); b.click();`,
    after: 2500,
    check: `(() => { const rows = [...document.querySelectorAll('.logline.clickable')];
      return __field('Host').value === 'edge-fw-02' && /[?&]host=edge-fw-02(&|$)/.test(location.hash) && !document.querySelector('[role=dialog]')
        && rows.length > 0 && rows.every((r) => r.querySelector('.c.hn').textContent === 'edge-fw-02'); })()`,
  },
  {
    name: 'events-click-app-adds-to-list',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=24h&app=sshd',
    wait: 2500,
    act: `__set(__field('Program/tag'), 'sshd, kernel'); document.querySelector('form[role=search]').requestSubmit();
      await new Promise((r) => setTimeout(r, 2000));
      const b = document.querySelector('.logline.clickable .c.ap.cell'); if (!b) throw new Error('no app cell'); window.__app = b.textContent; b.click();`,
    after: 2000,
    check: `__field('Program/tag').value === 'sshd, kernel' && [...document.querySelectorAll('.logline.clickable .c.ap')].every((x) => ['sshd', 'kernel'].includes(x.textContent))`,
  },
  {
    name: 'events-exclude-regex-error',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny&re=1&ex=(tcp&r=1h',
    wait: 1500,
    check: `document.querySelector('#ex-err')?.textContent.startsWith('error parsing regexp') && !document.querySelector('#sq-err')`,
  },
  {
    name: 'events-export-keeps-fields',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h&app=%25FW-*&host=edge-fw-01&ex=denied',
    wait: 2000,
    act: `__btn('Export these results').click();`,
    after: 1500,
    check: `(() => { const b = JSON.parse(window.__woodshedMock.lastExportBody || '{}');
      return location.hash.startsWith('#/export?') && document.querySelector('#exapp').value === '%FW-*' && document.querySelector('#exhost').value === 'edge-fw-01'
        && document.querySelector('#exex').value === 'denied' && b.app?.[0] === '%FW-*' && b.host?.[0] === 'edge-fw-01' && b.exclude === 'denied'; })()`,
  },
  // ---- Events v2: field panel, histogram, Text | Terms | Regex, saved searches (SPEC §10.1) ----
  // With the field panel beside the results (1,100 px and wider), "Export these results" stays on the Results
  // bar's first line, next to the title.
  ...[1100, 1400].map((w) => ({
    name: `events2-results-bar-${w}-light`,
    mode: 'light',
    w,
    url: '/?mock_panel=0#/events?q=deny&r=24h',
    wait: 3500,
    check: `(() => { const bar = document.querySelector('section[aria-label=Results] .bar'); const title = bar.querySelector('b');
      const exp = [...bar.querySelectorAll('button')].find((b) => b.textContent.includes('Export these results'));
      const fp = document.querySelector('aside.fp'); const res = document.querySelector('section[aria-label=Results]');
      return !!exp && Math.abs(exp.getBoundingClientRect().top - title.getBoundingClientRect().top) < 12
        && fp.getBoundingClientRect().right <= res.getBoundingClientRect().left && bar.innerText.includes('Scanned'); })()`,
  })),
  ...both({
    name: 'events2-panel',
    url: '/?mock_panel=0#/events?r=1h',
    wait: 3500,
    check: `(() => { const fp = document.querySelector('aside.fp'); const heads = [...fp.querySelectorAll('h3')].map((h) => h.textContent.trim().split(/\\s{2,}|\\d/)[0].trim());
      return heads.join('|') === 'Device|Severity|Facility|Host|Program/tag' && fp.querySelectorAll('li.row button.val').length > 10
        && fp.innerText.includes('Counted all of') && !fp.innerText.includes('≈')
        && document.querySelector('.histwrap').innerText.includes('from the index') && document.querySelectorAll('.hist .bar').length === 60; })()`,
  }),
  ...both({
    name: 'events2-histogram-partial',
    url: '/?mock_panel=0&mock_slow_summary=1#/events?q=deny&r=24h',
    wait: 2500,
    check: `document.querySelectorAll('.hist .bar.pending').length > 10 && document.querySelectorAll('.hist .bar .fill:not(.hatch)').length > 0
      && /Counted .+–.+ of .+–.+/.test(document.querySelector('aside.fp').innerText) && !document.querySelector('aside.fp').innerText.includes('Counted all') && document.querySelector('.histwrap').innerText.includes('not counted yet')`,
  }),
  ...both({
    name: 'events2-count-the-rest',
    url: '/?mock_panel=0&mock_slow_summary=1&mock_latency=20#/events?q=deny&r=24h',
    wait: 9000,
    check: `!!__btn('Count the rest') && document.querySelector('aside.fp').innerText.includes('Counting stopped after 60 s of scanning')`,
  }),
  {
    name: 'events2-count-the-rest-continues',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_slow_summary=1&mock_latency=20#/events?q=deny&r=24h',
    wait: 9000,
    // The whole "Counted <range> of <range>" line: its first word is a date when the range has one.
    act: `window.__c0 = document.querySelector('aside.fp').innerText.match(/Counted ([^\\n]+)/)[1]; __btn('Count the rest').click();`,
    after: 2500,
    check: `document.querySelector('aside.fp').innerText.match(/Counted ([^\\n]+)/)[1] !== window.__c0`,
  },
  {
    name: 'events2-expired-summary-restarts',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_slow_summary=1&mock_latency=20#/events?q=deny&r=24h',
    wait: 2000,
    act: `window.__woodshedMock.expireSummaries();`,
    after: 2500,
    check: `window.__woodshedMock.expiredSummaries === 1 && !document.querySelector('aside.fp [role=alert]') && document.querySelector('aside.fp').innerText.includes('Counting…')`,
  },
  {
    name: 'events2-terms-error-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny%20(tcp&syn=terms&r=1h',
    wait: 1500,
    check: `document.querySelector('#sq-err')?.textContent === 'Missing ")" for the "(" at character 6.' && __btn('Terms').getAttribute('aria-pressed') === 'true'`,
  },
  {
    name: 'events2-terms-results-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny%20NOT%20udp&syn=terms&r=24h',
    wait: 3000,
    check: `(() => { const rows = [...document.querySelectorAll('.logline.clickable')];
      return rows.length > 20 && rows.every((r) => /deny/i.test(r.textContent) && !/udp/i.test(r.textContent))
        && [...document.querySelectorAll('mark.hl')].every((m) => m.textContent.toLowerCase() === 'deny'); })()`,
  },
  {
    name: 'events2-regex-and-terms-switch',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny&r=1h',
    act: `__btn('Regex').click(); await __tick(); __btn('Terms').click(); await __tick(); document.querySelector('form[role=search]').requestSubmit();`,
    after: 1500,
    check: `/[?&]syn=terms(&|$)/.test(location.hash) && !/[?&]re=1/.test(location.hash) && __btn('Regex').getAttribute('aria-pressed') === 'false'`,
  },
  ...both({
    name: 'events2-saved-menu',
    url: '/?mock_panel=0#/events?r=1h',
    wait: 2500,
    act: `[...document.querySelectorAll('button')].find((b) => b.textContent.trim().startsWith('Saved')).click();`,
    after: 800,
    check: `(() => { const m = document.querySelector('[role=dialog][aria-label="Saved searches"]');
      return !!m && m.innerText.includes('Edge denies') && m.innerText.includes('Auth failures') && !!__btn('Save as…'); })()`,
  }),
  {
    name: 'events2-saved-open-missing-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h',
    wait: 2000,
    act: `[...document.querySelectorAll('button')].find((b) => b.textContent.trim().startsWith('Saved')).click(); await new Promise((r) => setTimeout(r, 700));
      [...document.querySelectorAll('[role=dialog] button.open')].find((b) => b.textContent.includes('Auth failures')).click();`,
    after: 2500,
    check: `document.querySelector('.savedline s')?.textContent === '10.9.9.9' && document.querySelector('.savedline').innerText.includes('no longer known')
      && /[?&]saved=ss_/.test(location.hash) && document.querySelector('#sq').value === 'failed' && !document.querySelector('.savedline .badge')`,
  },
  {
    name: 'events2-saved-changed-and-save-as',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h',
    wait: 2000,
    act: `const saved = () => [...document.querySelectorAll('button')].find((b) => b.textContent.trim().startsWith('Saved'));
      saved().click(); await new Promise((r) => setTimeout(r, 700));
      [...document.querySelectorAll('[role=dialog] button.open')].find((b) => b.textContent.includes('Edge denies')).click();
      await new Promise((r) => setTimeout(r, 2000));
      __set(document.querySelector('#sq'), 'deny NOT 10.1.0.255 NOT 10.1.0.254'); await __tick();
      if (!document.querySelector('.savedline .badge')) throw new Error('no changed badge');
      saved().click(); await new Promise((r) => setTimeout(r, 700)); __btn('Save as…').click(); await __tick();
      __set(document.querySelector('#ss-name'), 'Edge denies'); await __tick();
      document.querySelector('form.nameform').requestSubmit(); await new Promise((r) => setTimeout(r, 700));
      if (!document.querySelector('#ss-err')?.textContent.includes('already exists')) throw new Error('no name clash');
      __set(document.querySelector('#ss-name'), '  Edge denies, two gateways  '); await __tick();
      document.querySelector('form.nameform').requestSubmit();`,
    after: 1500,
    check: `document.querySelector('.savedline b')?.textContent === 'Edge denies, two gateways' && !document.querySelector('.savedline .badge')`,
  },
  {
    name: 'events2-click-value-filters',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=24h',
    wait: 3000,
    act: `const sec = [...document.querySelectorAll('aside.fp section')].find((x) => x.querySelector('h3').textContent.startsWith('Host'));
      const b = sec.querySelector('button.val'); window.__v = b.textContent; b.click();`,
    after: 2500,
    check: `(() => { const rows = [...document.querySelectorAll('.logline.clickable')];
      return __field('Host').value === window.__v && rows.length > 0 && rows.every((r) => r.querySelector('.c.hn').textContent.toLowerCase() === window.__v.toLowerCase())
        && [...document.querySelectorAll('aside.fp .chip')].some((c) => c.textContent.startsWith(window.__v)); })()`,
  },
  {
    name: 'events2-alt-click-excludes-light',
    mode: 'light',
    url: '/?mock_panel=0#/events?r=24h',
    wait: 3000,
    act: `const sec = [...document.querySelectorAll('aside.fp section')].find((x) => x.querySelector('h3').textContent.startsWith('Program/tag'));
      const b = sec.querySelector('button.val'); window.__v = b.textContent; b.dispatchEvent(new MouseEvent('click', { bubbles: true, altKey: true }));`,
    after: 3000,
    check: `(() => { const rows = [...document.querySelectorAll('.logline.clickable')]; const k = (x) => x.replace(/^%/, '').toLowerCase();
      return new URLSearchParams(location.hash.split('?')[1]).get('xapp') === window.__v && rows.length > 0 && rows.every((r) => k(r.querySelector('.c.ap').textContent) !== k(window.__v))
        && [...document.querySelectorAll('aside.fp .chip.out')].some((c) => c.textContent.startsWith('not ' + window.__v)); })()`,
  },
  {
    name: 'events2-minus-severity-sends-complement',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h',
    wait: 3000,
    act: `document.querySelector('aside.fp [aria-label="Leave out info"]').click();`,
    after: 2500,
    check: `new URLSearchParams(location.hash.split('?')[1]).get('sev') === '0,1,2,3,4,5,7,unknown'
      && [...document.querySelectorAll('.logline.clickable .c.s')].every((s) => s.textContent.trim() !== 'info')`,
  },
  {
    name: 'events2-chip-removes-filter',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h&fac=23&xhost=edge-fw-01',
    wait: 2500,
    act: `[...document.querySelectorAll('aside.fp .chip')].find((c) => c.textContent.startsWith('not edge-fw-01')).click();`,
    after: 2000,
    check: `(() => { const p = new URLSearchParams(location.hash.split('?')[1]); return !p.has('xhost') && p.get('fac') === '23'
      && [...document.querySelectorAll('aside.fp .chip')].some((c) => c.textContent.startsWith('local7')); })()`,
  },
  {
    name: 'events2-none-row-not-clickable',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=24h',
    wait: 3500,
    check: `(() => { const r = [...document.querySelectorAll('aside.fp li.static')].filter((li) => li.textContent.includes('(none)'));
      return r.length > 0 && r.every((li) => !li.querySelector('button')); })()`,
  },
  {
    name: 'events2-drag-zooms-and-back',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?r=1h',
    wait: 3000,
    act: `const h = document.querySelector('.hist'); const r = h.getBoundingClientRect(); const x = (i) => r.left + (i + 0.5) * r.width / 60;
      const ev = (t, i) => h.dispatchEvent(new PointerEvent(t, { bubbles: true, clientX: x(i), clientY: r.top + 30, pointerId: 1, button: 0 }));
      ev('pointerdown', 10); ev('pointermove', 15); ev('pointermove', 19); ev('pointerup', 19);
      await new Promise((res) => setTimeout(res, 2500));
      const p = new URLSearchParams(location.hash.split('?')[1]);
      window.__zoom = (Date.parse(p.get('to')) - Date.parse(p.get('from'))) / 60000;
      window.__bars = document.querySelectorAll('.hist .bar').length;
      history.back();`,
    after: 2500,
    check: `window.__zoom === 10 && window.__bars === 120 && new URLSearchParams(location.hash.split('?')[1]).get('r') === '1h' && !location.hash.includes('from=')`,
    report: `JSON.stringify({ zoom: window.__zoom, bars: window.__bars, hash: location.hash })`,
  },
  {
    name: 'events2-export-carries-new-filters',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/events?q=deny%20NOT%20udp&syn=terms&r=1h&fac=23&xapp=kernel&xdev=10.1.0.2',
    wait: 2500,
    act: `__btn('Export these results').click();`,
    after: 1500,
    check: `(() => { const b = JSON.parse(window.__woodshedMock.lastExportBody || '{}');
      return b.syntax === 'terms' && b.q === 'deny NOT udp' && JSON.stringify(b.facilities) === '[23]' && b.exclude_app?.[0] === 'kernel'
        && b.exclude_devices?.[0] === '10.1.0.2' && __btn('Terms').getAttribute('aria-pressed') === 'true' && document.body.innerText.includes('not program/tag: kernel'); })()`,
    report: `window.__woodshedMock.lastExportBody`,
  },
  ...both({
    name: 'dashboard-open-in-events',
    url: '/?mock_panel=0#/dashboard',
    wait: 3000,
    check: `(() => { const a = [...document.querySelectorAll('a.tail-btn')].find((x) => x.textContent.trim() === 'Open in Events');
      return !!a && a.getAttribute('href') === '#/events?r=1h'; })()`,
  }),
  {
    name: 'open-in-events-carries-tail-view',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_rate=200#/dashboard',
    wait: 2500,
    act: `[...document.querySelectorAll('[role=tab]')].find((t) => t.textContent.trim() === 'HQ').click();
      __set(document.querySelector('input[type=search]'), 'deny'); await __tick();
      [...document.querySelectorAll('a.tail-btn')].find((x) => x.textContent.trim() === 'Open in Events').click();`,
    after: 2500,
    check: `(() => { const p = new URLSearchParams(location.hash.split('?')[1]);
      const rows = [...document.querySelectorAll('.logline.clickable')];
      return location.hash.startsWith('#/events?') && p.get('q') === 'deny' && p.get('group') === 'HQ' && p.get('r') === '1h'
        && document.querySelector('#sq').value === 'deny' && rows.length > 0 && rows.every((r) => r.textContent.toLowerCase().includes('deny')); })()`,
  },

  // ---- Export ----
  ...both({
    name: 'export-estimate',
    url: '/?mock_panel=0#/export',
    wait: 1800,
    check: `/Up to [\\d,]+ lines from [\\d,]+ files?, about/.test(document.body.innerText)`,
  }),
  {
    name: 'export-building-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_export_secs=30#/export',
    wait: 1500,
    act: `__btn('Build the zip').click();`,
    after: 3500,
    check: `!!document.querySelector('li[data-state=building] [role=progressbar]')`,
  },
  {
    name: 'export-ready-list-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_export_secs=2#/export',
    wait: 1500,
    act: `__btn('Build the zip').click();`,
    after: 5000,
    check: `document.querySelectorAll('li[data-state=ready] a[download]').length >= 2 && document.body.innerText.includes('expires in 23 h')
      && document.body.innerText.includes('err, warn · “deny”') && document.body.innerText.includes('Group: DMZ')`,
  },
  {
    name: 'export-lifecycle',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_export_secs=2#/export',
    wait: 1500,
    act: `const before = new Set([...document.querySelectorAll('li[data-id]')].map((x) => x.dataset.id));
      __btn('Build the zip').click();
      await new Promise((r) => setTimeout(r, 1200));
      const mine = [...document.querySelectorAll('li[data-id]')].find((x) => !before.has(x.dataset.id));
      if (!mine || !['queued', 'building'].includes(mine.dataset.state)) throw new Error('not queued/building: ' + mine?.dataset.state);
      window.__exportId = mine.dataset.id;
      await new Promise((r) => setTimeout(r, 3500));
      const done = document.querySelector('li[data-id="' + window.__exportId + '"]');
      if (done?.dataset.state !== 'ready' || !done.querySelector('a[download]')) throw new Error('not ready: ' + done?.dataset.state);
      [...done.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Delete').click();`,
    after: 1200,
    check: `!document.querySelector('li[data-id="' + window.__exportId + '"]')`,
  },
  {
    name: 'export-all-devices-flag',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_devices=10000#/export',
    wait: 2500,
    check: `(() => { const b = JSON.parse(window.__woodshedMock.lastExportBody || '{}');
      return b.all_devices === true && !('devices' in b) && /Up to [\\d,]+ lines/.test(document.body.innerText)
        && /[\\d,]{5,} devices/.test(document.body.innerText); })()`,
  },
  {
    name: 'groups-from-api',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_devices=10000#/dashboard',
    wait: 2500,
    check: `['Stores', 'Warehouses', 'Lab', 'HQ', 'Ungrouped'].every((g) => [...document.querySelectorAll('[role=tab]')].some((t) => t.textContent.trim() === g))`,
  },
  ...[
    ['lan', '/?mock_panel=0&mock_auth=1&mock_loggedin=1#/export'],
    ['require-login-local', '/?mock_panel=0&mock_require_local=1&mock_loggedin=1#/export'],
  ].map(([mode, url]) => ({
    name: `export-download-with-ticket-${mode}`,
    noshot: true,
    mode: 'light',
    url,
    wait: 2000,
    act: `const m = window.__woodshedMock;
      if (await m.navigateStatus('/api/exports/exp_7Hq2/download') !== 401) throw new Error('a plain link should get 401');
      document.querySelector('li[data-state=ready] a[download]').click();
      await new Promise((r) => setTimeout(r, 1500));
      const d = m.downloads[m.downloads.length - 1];
      if (!d || !d.ticket || m.lastDownloadStatus !== 200) throw new Error('download failed: ' + m.lastDownloadStatus);
      // single-use: the same URL a second time is refused
      if (!m.lastTicketUrl.includes('ticket=')) throw new Error('no ticket issued');
      window.__reuse = await m.navigateStatus(m.lastTicketUrl);`,
    after: 300,
    check: `window.__reuse === 401 && !document.querySelector('[role=alert]') && !!__btn('Log out')`,
  })),
  {
    name: 'export-failure-shows-error',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_export_secs=2&mock_export_fail=1#/export',
    wait: 1500,
    act: `__btn('Build the zip').click();`,
    after: 2500,
    check: `[...document.querySelectorAll('li[data-state=failed]')].some((x) => x.textContent.includes('Not enough free disk space'))`,
  },
  {
    name: 'export-cancel-and-failure',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_export_secs=30&mock_export_fail=1#/export',
    wait: 1500,
    act: `__btn('Build the zip').click(); await new Promise((r) => setTimeout(r, 1500)); __btn('Build the zip').click();
      await new Promise((r) => setTimeout(r, 1500));
      const q = document.querySelector('li[data-state=queued]');
      if (!q) throw new Error('second export not queued');
      window.__q = q.dataset.id;
      [...q.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Cancel').click();`,
    after: 1500,
    check: `!document.querySelector('li[data-id="' + window.__q + '"]')`,
  },
  // ---- LAN mode and auth ----
  ...both({
    name: 'login',
    url: '/?mock_panel=0&mock_auth=1#/devices',
    check: `!!__field('Password') && !document.querySelector('nav') && !document.querySelector('input[type=search]')
      && document.body.innerText.includes('Forgot the password?')`,
  }),
  {
    name: 'login-forgot-password-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1#/devices',
    act: `document.querySelector('details summary').click();`,
    check: `document.body.innerText.includes('woodshed reset-password') && document.body.innerText.includes(\`http://localhost:\${location.port}/\`)`,
  },
  {
    name: 'login-wrong-password-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1#/devices',
    act: `__set(__field('Password'), 'not-it'); await __tick(); __btn('Log in').click();`,
    after: 800,
    check: `document.body.innerText.includes("That password isn't right.")`,
  },
  {
    name: 'login-locked-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1&mock_locked=1#/devices',
    act: `__set(__field('Password'), 'woodshed-demo'); await __tick(); __btn('Log in').click();`,
    after: 1200,
    check: `/locked for 1[45] min \\d+ s/.test(document.body.innerText) && __btn('Log in').disabled`,
  },
  {
    name: 'login-returns-and-sends-secret',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1#/devices',
    act: `__set(__field('Password'), 'woodshed-demo'); await __tick(); __btn('Log in').click();
      await new Promise(r => setTimeout(r, 1500));
      document.querySelector('[aria-label="Rename edge-fw-01"]').click(); await new Promise(r => setTimeout(r, 200));
      const i = document.getElementById('edit-name-10.1.0.1'); __set(i, 'edge-fw-01b');
      i.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));`,
    after: 900,
    check: `(() => { const m = window.__woodshedMock; const key = 'woodshed.session.' + location.origin;
      return location.hash === '#/devices' && !!__btn('Log out') && document.body.innerText.includes('edge-fw-01b')
        && m.secret.length === 32 && localStorage.getItem(key) === m.secret
        && m.lastWriteHeader === m.secret && m.lastGetHeader === m.secret
        && m.sessionBodies.length > 0 && m.sessionBodies.every((b) => !b.includes(m.secret) && !b.includes('session_secret')); })()`,
  },
  {
    name: 'secret-sent-on-gets-and-live-stream',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1&mock_loggedin=1#/dashboard',
    wait: 3000,
    check: `(() => { const m = window.__woodshedMock; return !!m.secret && m.lastGetHeader === m.secret && m.lastLiveHeader === m.secret
      && document.querySelectorAll('[role=log] .logline').length > 0; })()`,
  },
  {
    name: 'cookie-without-header-gets-401-and-login',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1&mock_loggedin=1#/devices',
    wait: 1500,
    act: `window.__woodshedMock.cookieOnly = true;
      await new Promise((r) => setTimeout(r, 6000));
      if (!__field('Password') || document.querySelector('nav')) throw new Error('no login after a cookie-only 401');
      if (localStorage.getItem('woodshed.session.' + location.origin)) throw new Error('secret not cleared on 401');
      window.__woodshedMock.cookieOnly = false;
      __set(__field('Password'), 'woodshed-demo'); await __tick(); __btn('Log in').click();`,
    after: 1500,
    check: `location.hash === '#/devices' && document.querySelectorAll('tbody tr').length > 5`,
  },
  {
    name: 'logout-clears-secret',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_auth=1&mock_loggedin=1#/about',
    wait: 1500,
    act: `__btn('Log out').click();`,
    after: 1200,
    check: `!!__field('Password') && !localStorage.getItem('woodshed.session.' + location.origin)`,
  },
  {
    name: 'expired-session-401-shows-login',
    noshot: true,
    mode: 'light',
    url: '/?mock_auth=1&mock_loggedin=1#/settings',
    act: `__btn('Mock data ▸').click(); await new Promise(r => setTimeout(r, 200)); __btn('Expire session').click();
      await new Promise(r => setTimeout(r, 1200));
      if (!__field('Password') || document.querySelector('nav')) throw new Error('no login form after the 401');
      __set(__field('Password'), 'woodshed-demo'); await __tick(); __btn('Log in').click();`,
    after: 1500,
    check: `location.hash === '#/settings' && document.body.innerText.includes('UI access') && !!document.querySelector('nav')`,
  },
  {
    name: 'password-set-enables-lan',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0#/settings',
    act: `const lan = document.querySelector('[aria-describedby^="hint-lan"]'); if (!lan.disabled) throw new Error('LAN enabled without a password');
      __set(__field('New password'), 'short'); __set(__field('Repeat it'), 'short'); await __tick(); __btn('Set password').click();
      await new Promise(r => setTimeout(r, 600));
      if (!document.body.innerText.includes('Use 8 to 1024 characters.')) throw new Error('no length error');
      __set(__field('New password'), 'correct horse'); __set(__field('Repeat it'), 'correct horse'); await __tick(); __btn('Set password').click();`,
    after: 800,
    check: `document.body.innerText.includes('Password set. Login is now required on this machine too; you can turn it off below.')
      && !document.querySelector('[aria-describedby^="hint-lan"]').disabled && __field('Require login on this machine too').checked
      && !!__btn('Log out') && !__field('Password')`,
  },
  {
    name: 'settings-lan-warning-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_password=1#/settings',
    act: `document.querySelector('[aria-describedby^="hint-lan"]').click();`,
    check: `document.body.innerText.includes('Before you turn this on')`,
  },
  {
    name: 'settings-lan-saved-windows-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_password=1&mock_os=windows#/settings',
    act: `document.querySelector('[aria-describedby^="hint-lan"]').click(); __btn('Save').click();`,
    after: 900,
    check: `document.body.innerText.includes('netsh advfirewall firewall add rule name="Woodshed UI" dir=in action=allow protocol=TCP localport=8514')
      && [...document.querySelectorAll('a')].some((a) => a.textContent.trim() === 'Go there' && a.href.startsWith('https://'))`,
  },
  {
    name: 'settings-lan-on-dark',
    mode: 'dark',
    url: '/?mock_panel=0&mock_auth=1&mock_loggedin=1#/settings',
    check: `!!__field('Current password') && !!__btn('Log out') && document.body.innerText.includes('Certificate fingerprint (SHA-256)')`,
  },
  { name: 'mock-panel-light', mode: 'light', url: '/#/dashboard', act: `__btn('Mock data ▸').click();`, after: 500 },
  // ---- 1.1: the TLS syslog listener (SPEC §10.3) ----
  ...both({
    name: 'settings-tls',
    url: '/?mock_panel=0#/settings?section=tls',
    act: `document.getElementById('tls-help').open = true; __only('tls');`,
    check: `document.body.innerText.includes('Syslog over TLS') && document.body.innerText.includes('CA certificate')
      && document.querySelectorAll('#tls .fp').length === 3 && !!__btn('Download PEM') && !!__btn('Renew certificate…')
      && document.body.innerText.includes('sudo ufw allow 6514/tcp') === false`,
  }),
  {
    name: 'settings-tls-linux-help-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_os=linux#/settings?section=tls-failures',
    act: `document.getElementById('tls-help').open = true; __only('tls');`,
    check: `document.body.innerText.includes('sudo ufw allow 6514/tcp')
      && document.body.innerText.includes('sudo firewall-cmd --permanent --add-port=6514/tcp && sudo firewall-cmd --reload')`,
  },
  {
    name: 'settings-tls-replace-ca-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings?section=tls',
    act: `__only('tls'); scrollTo(0, 0); __btn('Replace CA…').click();`,
    check: `document.querySelector('[role=alertdialog]')?.innerText.includes('Every device must import the new CA certificate again')
      && __btn('Replace CA').disabled`,
  },
  {
    name: 'settings-tls-renew-dialog-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings?section=tls',
    act: `__only('tls'); scrollTo(0, 0); __btn('Renew certificate…').click();`,
    check: `document.querySelector('[role=alertdialog]')?.innerText.includes('Devices keep working')`,
  },
  {
    name: 'tls-renew-keeps-ca',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_tls_expiring=1#/settings?section=tls',
    wait: 2500,
    act: `const ca = document.querySelectorAll('#tls .fp')[0].textContent, leaf = document.querySelectorAll('#tls .fp')[2].textContent;
      if (!document.body.innerText.includes('The TLS syslog certificate expires on')) throw new Error('no expiring banner');
      __btn('Renew certificate…').click(); await __tick(); __btn('Renew certificate').click();
      await new Promise((r) => setTimeout(r, 2500));
      window.__ok = document.querySelectorAll('#tls .fp')[0].textContent === ca && document.querySelectorAll('#tls .fp')[2].textContent !== leaf;`,
    after: 5500,
    check: `window.__ok && document.body.innerText.includes('The certificate was renewed') && !document.body.innerText.includes('The TLS syslog certificate expires on')`,
  },
  {
    name: 'settings-tls-failures-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings?section=tls-failures',
    act: `__only('tls');`,
    check: `document.body.innerText.includes('Failed TLS handshakes, last 24 h') && document.body.innerText.includes('Not TLS: usually plain syslog sent to the TLS port')
      && !!document.querySelector('#tls a[href="#/devices?q=10.8.0.1"]')`,
  },
  {
    name: 'banners-tls-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_os=windows&mock_tls_legacy=1&mock_tls_expiring=1&mock_tls_names=1&mock_tls_firewall=disabled#/dashboard',
    check: `document.querySelectorAll('.banner').length >= 4 && [...document.querySelectorAll('button')].filter((b) => b.textContent.trim() === 'Open TLS settings').length === 2
      && document.body.innerText.includes('woodshed tls on')`,
  },
  {
    name: 'tls-banner-opens-settings',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_tls_names=1#/dashboard',
    act: `__btn('Open TLS settings').click();`,
    after: 1500,
    check: `location.hash === '#/settings?section=tls' && Math.abs(document.getElementById('tls').getBoundingClientRect().top) < 200`,
    report: `location.hash + ' top=' + document.getElementById('tls')?.getBoundingClientRect().top + ' y=' + scrollY`,
  },
  {
    name: 'devices-tls-light',
    mode: 'light',
    url: '/?mock_panel=0#/devices',
    act: `document.querySelector('[aria-label="TLS details for branch-fw-08"]').click(); document.querySelector('[aria-label="TLS details for edge-fw-02"]').click();`,
    check: `document.querySelectorAll('button.tls').length >= 4 && document.querySelectorAll('tr.tlsrow').length === 2
      && document.body.innerText.includes('No TLS version in common')`,
  },
  {
    name: 'devices-tls-dark',
    mode: 'dark',
    url: '/?mock_panel=0#/devices',
    act: `document.querySelector('[aria-label="TLS details for edge-fw-02"]').click();`,
  },
  {
    name: 'settings-tls-never-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_tls=never#/settings?section=tls',
    act: `__only('tls');`,
    check: `!!document.querySelector('[data-tls-none]') && document.querySelectorAll('button.tls').length === 0`,
  },
  {
    name: 'tls-first-turn-on-creates-cert',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_tls=never#/settings?section=tls',
    act: `__field('Syslog over TLS').click(); await __tick();
      if (!document.body.innerText.includes('Before you turn on TLS logging on a firewall')) throw new Error('no firewall warning');
      __btn('Save').click();`,
    after: 2500,
    check: `!document.querySelector('[data-tls-none]') && document.querySelectorAll('#tls .fp').length === 3`,
  },
  {
    name: 'settings-tls-off-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_tls=off#/settings?section=tls',
    act: `__only('tls');`,
    check: `document.body.innerText.includes('TLS is off.') && !__field('Syslog over TLS').checked`,
  },
  {
    name: 'settings-tls-file-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_tls=file#/settings?section=tls',
    act: `__only('tls');`,
    check: `document.body.innerText.includes('Your certificate') && !__btn('Download PEM') && !__btn('Renew certificate…')
      && __field('TLS certificate file').value === '/etc/woodshed/tls/fullchain.pem'`,
  },
  {
    name: 'settings-tls-errors-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_tls=file#/settings?section=tls',
    act: `__set(__field('TLS port'), '514'); __set(__field('TLS certificate file'), '/etc/woodshed/tls/mismatch.pem'); await __tick(); __btn('Save').click();
      await new Promise((r) => setTimeout(r, 800)); __only('tls');`,
    check: `document.querySelectorAll('#tls .ferr').length === 3`,
  },
  {
    name: 'settings-tls-windows-firewall-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_os=windows&mock_tls_firewall=missing#/settings?section=tls',
    act: `__only('tls');`,
    check: `!!document.querySelector('[data-tls-firewall]') && document.querySelector('[data-tls-firewall]').innerText.includes('woodshed tls on')`,
  },

  // The update check (docs/api.md → Update check): mock_updates makes it a release build.
  ...both({
    name: 'banner-update-prompt',
    url: '/?mock_panel=0&mock_updates=ask#/dashboard',
    check: `(() => { const b = [...document.querySelectorAll('.banner')].find((x) => x.innerText.includes('Check for new Woodshed versions once a day?'));
      return !!b && !!__btn('Turn on') && !!__btn('No thanks') && !b.querySelector('.x'); })()`,
  }),
  ...both({
    name: 'banner-update-available',
    url: '/?mock_panel=0&mock_updates=on#/dashboard',
    check: `document.body.innerText.includes('Woodshed 1.2.0 is available (this is 1.1.0).')
      && [...document.querySelectorAll('.banner a')].some((a) => a.href === 'https://github.com/gmccollu/woodshed/releases/tag/v1.2.0')`,
  }),
  {
    name: 'update-turn-on-clears-prompt',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=ask#/dashboard',
    act: `__btn('Turn on').click();`,
    after: 4500,
    check: `!document.body.innerText.includes('Check for new Woodshed versions') && document.body.innerText.includes('Woodshed 1.2.0 is available')`,
  },
  {
    name: 'update-no-thanks-clears-prompt',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=ask#/dashboard',
    act: `__btn('No thanks').click();`,
    after: 1500,
    check: `!document.body.innerText.includes('Check for new Woodshed versions') && !document.body.innerText.includes('is available')`,
  },
  {
    name: 'update-dismiss-hides-version',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=on#/dashboard',
    act: `document.querySelector('[aria-label="Hide this until a newer version"]').click();`,
    after: 1500,
    check: `!document.body.innerText.includes('Woodshed 1.2.0 is available')`,
  },
  ...both({
    name: 'settings-updates',
    url: '/?mock_panel=0&mock_updates=on#/settings?section=updates',
    clip: 'section[aria-labelledby="updates"]',
    check: `(() => { const t = document.querySelector('section[aria-labelledby="updates"]')?.innerText ?? '';
      return t.includes('Check for new versions once a day') && t.includes('gmccollu.github.io/woodshed/releases.json')
        && t.includes('Woodshed 1.2.0 is available (this is 1.1.0), checked 3 h ago') && t.includes('Next check') && !!__btn('Check now'); })()`,
  }),
  {
    name: 'settings-updates-check-now-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=on&mock_update_result=latest#/settings?section=updates',
    clip: 'section[aria-labelledby="updates"]',
    act: `__btn('Check now').click();`,
    after: 3500,
    check: `document.querySelector('section[aria-labelledby="updates"]').innerText.includes('OK, 1.1.0 is the latest (checked just now)')`,
  },
  {
    name: 'settings-updates-failed-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=on&mock_update_result=error#/settings?section=updates',
    clip: 'section[aria-labelledby="updates"]',
    check: `document.querySelector('section[aria-labelledby="updates"]').innerText.includes('Last check failed 3 h ago: TLS certificate not trusted (a proxy that inspects HTTPS?)')`,
  },
  {
    name: 'settings-updates-ask-light',
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=ask#/settings?section=updates',
    clip: 'section[aria-labelledby="updates"]',
    check: `(() => { const s = document.querySelector('section[aria-labelledby="updates"]'); return s.innerText.includes('Not decided yet')
      && !s.querySelector('input[type=checkbox]').checked && __btn('Check now').disabled; })()`,
  },
  {
    name: 'settings-updates-dev-build-light',
    mode: 'light',
    url: '/?mock_panel=0#/settings?section=updates',
    clip: 'section[aria-labelledby="updates"]',
    check: `document.querySelector('section[aria-labelledby="updates"]').innerText.includes('Not available in this build (0.1.0)')
      && !document.body.innerText.includes('Check for new Woodshed versions')`,
  },
  {
    name: 'settings-update-switch-then-save',
    noshot: true,
    mode: 'light',
    url: '/?mock_panel=0&mock_updates=on#/settings',
    act: `document.querySelector('section[aria-labelledby="updates"] input[type=checkbox]').click(); await new Promise((r) => setTimeout(r, 1200));
      __set(__field('Keep logs for'), '14'); await __tick(); __btn('Save').click();`,
    after: 1500,
    check: `!document.body.innerText.includes('changed since you loaded them') && !document.body.innerText.includes('changed elsewhere')`,
  },
].filter((s) => s.name.includes(only));

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const profile = mkdtempSync(join(tmpdir(), 'woodshed-shots-'));
const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    `--remote-debugging-port=${PORT}`,
    `--user-data-dir=${profile}`,
    `--window-size=${W},${H}`,
    '--hide-scrollbars',
    '--no-first-run',
    '--no-default-browser-check',
    'about:blank',
  ],
  { stdio: 'ignore' },
);

async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* not up yet */
    }
    await sleep(200);
  }
  throw new Error('Chrome did not start');
}

let failed = 0;
try {
  const ws = new WebSocket(await target());
  await new Promise((r, j) => {
    ws.onopen = r;
    ws.onerror = j;
  });
  let id = 0;
  const pending = new Map();
  const events = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const { res, rej } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
    } else if (msg.method) events.push(msg);
  };
  const send = (method, params = {}) =>
    new Promise((res, rej) => {
      const n = ++id;
      pending.set(n, { res, rej });
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: `(async () => { ${H_JS}; ${expr} })()`, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };

  await send('Page.enable');
  await send('Runtime.enable');
  mkdirSync(OUT, { recursive: true });

  for (const s of SHOTS) {
    try {
      const sw = s.w ?? W;
      const sh = s.h ?? H;
      await send('Emulation.setDeviceMetricsOverride', { width: sw, height: sh, deviceScaleFactor: 1, mobile: false });
      // Fresh preferences per shot (wrap, severities, theme), so shots don't leak into each other.
      await send('Storage.clearDataForOrigin', { origin: new URL(BASE).origin, storageTypes: 'local_storage' });
      await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: s.mode }] });
      // A fresh document each time: blank first so the hash-only change reloads the app.
      await send('Page.navigate', { url: 'about:blank' });
      await sleep(150);
      await send('Page.navigate', { url: `${BASE}${s.url}` });
      await sleep(400);
      await evaluate(`localStorage.removeItem('woodshed.theme'); document.documentElement.classList.toggle('dark', ${s.mode === 'dark'});`);
      await sleep(s.wait ?? 2000);
      if (s.act) {
        await evaluate(s.act);
        await sleep(s.after ?? 600);
      }
      if (s.check && !(await evaluate(`return !!(${s.check})`))) {
        failed++;
        console.error(`  ! ${s.name}: check failed: ${s.check}`);
        if (s.report) console.error(`    ${await evaluate(`return ${s.report}`)}`);
      }
      const errs = events.filter((e) => e.method === 'Runtime.exceptionThrown');
      if (errs.length) {
        console.error(`  ! ${s.name}: page error: ${errs[0].params.exceptionDetails.exception?.description ?? errs[0].params.exceptionDetails.text}`);
        failed++;
      }
      events.length = 0;
      if (s.noshot) {
        console.log(`  ${s.name}: checked`);
        continue;
      }
      if (s.clip) {
        const r = JSON.parse(
          await evaluate(`const r = document.querySelector(${JSON.stringify(s.clip)}).getBoundingClientRect();
            return JSON.stringify({ x: r.left + scrollX - 16, y: r.top + scrollY - 16, width: r.width + 32, height: r.height + 32 });`),
        );
        const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { ...r, x: Math.max(0, r.x), y: Math.max(0, r.y), scale: 1 } });
        writeFileSync(join(OUT, `${s.name}.png`), Buffer.from(shot.data, 'base64'));
        console.log(`  ${s.name}.png (${Math.round(r.width)}x${Math.round(r.height)}, ${s.clip})`);
        continue;
      }
      const height = await evaluate('return Math.ceil(document.documentElement.scrollHeight)');
      // Long pages stop at 3000 px (the 10k-device list). Settings is one long form whose shots show a section near
      // its end (host names, LAN mode, storage), so it gets the whole page; since the TLS card it's past 3000.
      const maxH = s.maxh ?? (s.url.includes('#/settings') ? 6000 : 3000);
      const h = Math.max(sh, Math.min(height, maxH));
      await send('Emulation.setDeviceMetricsOverride', { width: sw, height: h, deviceScaleFactor: 1, mobile: false });
      await sleep(250);
      const shot = await send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: sw, height: h, scale: 1 } });
      writeFileSync(join(OUT, `${s.name}.png`), Buffer.from(shot.data, 'base64'));
      console.log(`  ${s.name}.png (${sw}x${h})`);
    } catch (e) {
      failed++;
      console.error(`  ! ${s.name}: ${e.message}`);
    }
  }
  ws.close();
} finally {
  chrome.kill();
  await sleep(300);
  rmSync(profile, { recursive: true, force: true });
}
process.exit(failed ? 1 : 0);

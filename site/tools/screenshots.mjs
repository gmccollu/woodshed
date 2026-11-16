// Review screenshots of the site at desktop and phone widths, light and dark, into
// site/screenshots-review/ (gitignored). Drives headless Chrome over the DevTools protocol.
// releases.json (written at deploy time) is served by the harness itself: a stable
// release, only a prerelease, neither, or a 404. Fails on any cross-origin request.
//
//   cd site && python3 -m http.server 8765 &
//   node tools/screenshots.mjs            (BASE=http://127.0.0.1:8765, CHROME=… to override)
//
// Also fails on any page error or CSP violation.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const CHROME = process.env.CHROME ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const BASE = process.env.BASE ?? 'http://127.0.0.1:8765';
const OUT = fileURLToPath(new URL('../screenshots-review/', import.meta.url));
const PORT = 9800 + Math.floor(Math.random() * 100);

// The release's file names (packaging commit 79b5d2f); X is the version.
const namesFor = (X) => [
  `woodshed_${X}_windows_amd64.msi`, `woodshed_${X}_windows_arm64.msi`, `woodshed_${X}_macos_universal.pkg`,
  `woodshed_${X}_amd64.deb`, `woodshed_${X}_arm64.deb`, `woodshed-${X}-1.x86_64.rpm`, `woodshed-${X}-1.aarch64.rpm`,
  `woodshed_${X}_windows_amd64.zip`, `woodshed_${X}_windows_arm64.zip`, `woodshed_${X}_darwin_universal.tar.gz`,
  `woodshed_${X}_linux_amd64.tar.gz`, `woodshed_${X}_linux_arm64.tar.gz`, 'checksums.txt',
];
const hex = (i) => [...Array(64)].map((_, k) => '0123456789abcdef'[(i * 7 + k * 13) % 16]).join('');
const releaseFor = (X) =>
  JSON.stringify({
    tag_name: `v${X}`,
    html_url: `https://github.com/gmccollu/woodshed/releases/tag/v${X}`,
    assets: namesFor(X).map((name, i) => ({
      name,
      size: name === 'checksums.txt' ? 1200 : 9_000_000 + i * 731_000,
      browser_download_url: `https://github.com/gmccollu/woodshed/releases/download/v${X}/${name}`,
      digest: name === 'checksums.txt' ? null : `sha256:${hex(i + 1)}`,
    })),
  });
const file = (stable, prerelease) => JSON.stringify({ generated_at: '2026-11-11T00:00:00Z', stable: stable && JSON.parse(stable), prerelease: prerelease && JSON.parse(prerelease) });
const FILES = {
  release: [200, file(releaseFor('1.0.0'), releaseFor('1.1.0-rc1'))],
  rc: [200, file(null, releaseFor('0.9.0-rc2'))],
  none: [200, file(null, null)],
  404: [404, 'Not Found'],
};

const WIN = { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36', meta: { platform: 'Windows', platformVersion: '15.0.0', architecture: 'x86', bitness: '64', model: '', mobile: false } };
const MAC = { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36', meta: { platform: 'macOS', platformVersion: '15.6.0', architecture: 'arm', bitness: '64', model: '', mobile: false } };
const LINUX_ARM = { ua: 'Mozilla/5.0 (X11; Linux aarch64; rv:140.0) Gecko/20100101 Firefox/140.0' };
const PHONE = { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1', mobile: true };

const both = (s) => [
  { ...s, name: `${s.name}-light`, mode: 'light' },
  { ...s, name: `${s.name}-dark`, mode: 'dark' },
];

// The hero demo plays (WebM first), or with reduced motion waits on its poster with controls.
const demoPlays = `(() => { const v = document.querySelector('.shot video.demo'); return !!v && !v.error && v.currentSrc.endsWith('/img/demo.webm') && !v.paused && !v.controls && v.readyState >= 2; })()`;
const demoStill = `(() => { const v = document.querySelector('.shot video.demo'); return !!v && v.paused && v.controls && v.currentTime === 0; })()`;

const SHOTS = [
  ...both({ name: 'home-desktop', path: '/', w: 1400, h: 900, client: WIN, rel: 'release',
    check: `${demoPlays} && document.querySelectorAll('#dl-primary .asset.best').length === 2 && document.querySelector('#dl-primary .asset .n').textContent === 'Windows installer (x64)' && document.querySelectorAll('#dl-others-body li').length === 10` }),
  ...both({ name: 'home-phone', path: '/', w: 390, h: 844, client: PHONE, rel: 'release',
    check: `document.querySelectorAll('#dl-primary .asset').length === 0 && document.getElementById('dl-others').open && document.querySelectorAll('#dl-others-body li').length === 12 && document.documentElement.scrollWidth <= innerWidth
      && [...document.querySelectorAll('#dl-others-body .file')].every((f) => f.getBoundingClientRect().right <= f.closest('li').getBoundingClientRect().right)
      && [...document.querySelectorAll('#dl-others-body .dl')].every((b) => b.textContent === 'Download')` }),
  { name: 'home-reduced-motion-light', mode: 'light', motion: 'reduce', path: '/', w: 1400, h: 900, client: WIN, rel: 'release', check: demoStill },
  { name: 'home-desktop-all-downloads-light', mode: 'light', path: '/#download', w: 1400, h: 900, client: WIN, rel: 'release',
    act: `(document.getElementById('dl-others').open = true, true)`,
    check: `[...document.querySelectorAll('#dl-others-body li')].every((li) => li.getBoundingClientRect().height < 80)` },
  { name: 'home-prerelease-dark', mode: 'dark', path: '/#download', w: 1400, h: 900, client: WIN, rel: 'rc',
    check: `document.querySelector('#dl-status').textContent === 'Release candidate 0.9.0-rc2 is available for testing. Downloads for Windows:'
      && document.querySelector('#dl-status b').textContent === 'Release candidate 0.9.0-rc2 is available for testing.'
      && !!document.getElementById('dl-rc-note') && [...document.querySelectorAll('#dl-primary .asset .f')][0].textContent.startsWith('woodshed_0.9.0-rc2_windows_amd64.msi')` },
  { name: 'home-mac-light', mode: 'light', path: '/#download', w: 1400, h: 900, client: MAC, rel: 'release',
    check: `[...document.querySelectorAll('#dl-primary .asset .n')].map((x) => x.textContent).join('|') === 'macOS installer (x64 and ARM64)|macOS portable (x64 and ARM64)'` },
  { name: 'home-linux-arm-dark', mode: 'dark', path: '/#download', w: 1400, h: 900, client: LINUX_ARM, rel: 'release',
    check: `document.querySelectorAll('#dl-primary .asset.best').length === 3 && document.querySelector('#dl-status').textContent.includes('on ARM')` },
  { name: 'home-fallback-light', mode: 'light', path: '/#download', w: 1400, h: 900, client: WIN, rel: 'none',
    check: `document.querySelector('#dl-status').textContent.startsWith('No release has been published yet') && document.querySelector('#dl-primary a.btn').href.endsWith('/woodshed/releases')` },
  { name: 'home-missing-dark', mode: 'dark', path: '/#download', w: 390, h: 844, client: PHONE, rel: '404',
    check: `document.querySelector('#dl-status').textContent.includes("isn't available here") && document.querySelector('#dl-primary a.btn').href.endsWith('/woodshed/releases')` },
  ...both({ name: 'install-desktop', path: '/install.html', w: 1400, h: 900, client: MAC, rel: 'release' }),
  ...both({ name: 'install-phone', path: '/install.html', w: 390, h: 844, client: PHONE, rel: 'release',
    check: `[...document.querySelectorAll('main *')].every((e) => e.closest('pre, table') || e.getBoundingClientRect().right <= innerWidth + 1)` }),
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const profile = mkdtempSync(join(tmpdir(), 'woodshed-site-'));
const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, '--hide-scrollbars', '--no-first-run', '--disable-extensions', 'about:blank'], { stdio: 'ignore' });

async function target() {
  for (let i = 0; i < 50; i++) {
    try {
      const page = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* starting */
    }
    await sleep(200);
  }
  throw new Error('Chrome did not start');
}

let failed = 0;
try {
  const ws = new WebSocket(await target());
  await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = j)));
  let id = 0;
  const pending = new Map();
  const events = [];
  let rel = 'release';
  let fileCalls = 0;
  const foreign = [];
  const send = (method, params = {}) =>
    new Promise((res, rej) => {
      const n = ++id;
      pending.set(n, { res, rej });
      ws.send(JSON.stringify({ id: n, method, params }));
    });
  ws.onmessage = async (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const { res, rej } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
    } else if (msg.method === 'Fetch.requestPaused') {
      fileCalls++;
      const [code, body] = FILES[rel];
      send('Fetch.fulfillRequest', {
        requestId: msg.params.requestId,
        responseCode: code,
        responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
        body: Buffer.from(body).toString('base64'),
      });
    } else if (msg.method === 'Network.requestWillBeSent') {
      const u = msg.params.request.url;
      // Only network requests count (a browser extension's own scripts aren't the site's).
      if (/^(https?|wss?):/.test(u) && new URL(u).origin !== new URL(BASE).origin) foreign.push(u);
    } else if (msg.method) events.push(msg);
  };
  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: `(async () => (${expr}))()`, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  };

  await send('Page.enable');
  await send('Runtime.enable');
  await send('Log.enable');
  await send('Network.enable');
  await send('Fetch.enable', { patterns: [{ urlPattern: `${BASE}/releases.json*` }] });
  mkdirSync(OUT, { recursive: true });

  for (const s of SHOTS) {
    try {
      rel = s.rel;
      fileCalls = 0;
      foreign.length = 0;
      await send('Storage.clearDataForOrigin', { origin: new URL(BASE).origin, storageTypes: 'all' });
      await send('Emulation.setDeviceMetricsOverride', { width: s.w, height: s.h, deviceScaleFactor: 1, mobile: !!s.client.mobile });
      await send('Emulation.setUserAgentOverride', { userAgent: s.client.ua, ...(s.client.meta ? { userAgentMetadata: { brands: [], fullVersionList: [], fullVersion: '140.0', ...s.client.meta } } : {}) });
      await send('Emulation.setEmulatedMedia', {
        features: [
          { name: 'prefers-color-scheme', value: s.mode },
          { name: 'prefers-reduced-motion', value: s.motion ?? 'no-preference' },
        ],
      });
      await send('Page.navigate', { url: 'about:blank' });
      await sleep(100);
      events.length = 0;
      await send('Page.navigate', { url: `${BASE}${s.path}` });
      await sleep(1500);
      const bad = events.filter(
        (e) => e.method === 'Runtime.exceptionThrown' || (e.method === 'Log.entryAdded' && /Content Security Policy|Refused to/i.test(e.params.entry.text)),
      );
      if (bad.length) {
        failed++;
        console.error(`  ! ${s.name}: ${JSON.stringify(bad[0].params).slice(0, 300)}`);
      }
      if (s.act) {
        await evaluate(s.act);
        await sleep(300);
      }
      if (s.check && !(await evaluate(s.check))) {
        failed++;
        console.error(`  ! ${s.name}: check failed: ${s.check}`);
      }
      if (foreign.length) {
        failed++;
        console.error(`  ! ${s.name}: ${foreign.length} cross-origin request(s): ${foreign.slice(0, 3).join(', ')}`);
      }
      const wantFile = s.path.startsWith('/install') ? 0 : 1;
      if (fileCalls !== wantFile) {
        failed++;
        console.error(`  ! ${s.name}: expected ${wantFile} request(s) for releases.json, saw ${fileCalls}`);
      }
      const height = Math.min(await evaluate('Math.ceil(document.documentElement.scrollHeight)'), 6000);
      await send('Emulation.setDeviceMetricsOverride', { width: s.w, height: Math.max(s.h, height), deviceScaleFactor: 1, mobile: !!s.client.mobile });
      await sleep(250);
      const shot = await send('Page.captureScreenshot', { format: 'png', clip: { x: 0, y: 0, width: s.w, height: Math.max(s.h, height), scale: 1 } });
      writeFileSync(join(OUT, `${s.name}.png`), Buffer.from(shot.data, 'base64'));
      console.log(`  ${s.name}.png (${s.w}x${Math.max(s.h, height)})`);
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

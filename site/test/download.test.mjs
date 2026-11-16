// Unit tests for site/download.js: cd site && npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, detectPlatform, loadRelease, pick, releasesUrl, RELEASES_FILE, REPO } from '../download.js';
import { summarize } from '../tools/releases.mjs';

// Every file the release workflow produces (packaging commit 79b5d2f): X is the version,
// "1.0.0" or a prerelease such as "0.9.0-rc2" (a hyphen, never "~" or ".rc").
const namesFor = (X) => [
  `woodshed_${X}_windows_amd64.msi`,
  `woodshed_${X}_windows_arm64.msi`,
  `woodshed_${X}_macos_universal.pkg`,
  `woodshed_${X}_amd64.deb`,
  `woodshed_${X}_arm64.deb`,
  `woodshed-${X}-1.x86_64.rpm`,
  `woodshed-${X}-1.aarch64.rpm`,
  `woodshed_${X}_windows_amd64.zip`,
  `woodshed_${X}_windows_arm64.zip`,
  `woodshed_${X}_darwin_universal.tar.gz`,
  `woodshed_${X}_linux_amd64.tar.gz`,
  `woodshed_${X}_linux_arm64.tar.gz`,
  'checksums.txt',
];
const releaseFor = (X) => ({
  tag_name: `v${X}`,
  html_url: `https://github.com/gmccollu/woodshed/releases/tag/v${X}`,
  assets: namesFor(X).map((name, i) => ({
    name,
    size: 1_000_000 + i,
    browser_download_url: `https://github.com/gmccollu/woodshed/releases/download/v${X}/${name}`,
    digest: `sha256:${String(i).padStart(64, '0')}`,
  })),
});
const NAMES = namesFor('1.0.0');
const RELEASE = releaseFor('1.0.0');

const names = (list) => list.map((a) => a.name);

test('every release file is classified; checksums.txt is kept apart', () => {
  for (const n of NAMES.slice(0, -1)) assert.ok(classify(n), n);
  assert.equal(classify('checksums.txt'), null);
  assert.equal(classify('woodshed_1.0.0_linux_amd64.tar.gz.intoto.jsonl'), null);
  assert.deepEqual(classify('woodshed_1.0.0_windows_arm64.msi'), { os: 'windows', kind: 'installer', arch: 'arm64', label: 'Windows installer (ARM64)', format: 'msi' });
  assert.equal(classify('woodshed-1.0.0-1.aarch64.rpm').arch, 'arm64');
  assert.equal(classify('woodshed_1.0.0_darwin_universal.tar.gz').kind, 'portable');
});

test('the best files per platform, installer first', () => {
  const p = (os, arch) => names(pick(RELEASE.assets, { os, arch }).best);
  assert.deepEqual(p('windows', 'x64'), ['woodshed_1.0.0_windows_amd64.msi', 'woodshed_1.0.0_windows_amd64.zip']);
  assert.deepEqual(p('windows', 'arm64'), ['woodshed_1.0.0_windows_arm64.msi', 'woodshed_1.0.0_windows_arm64.zip']);
  assert.deepEqual(p('windows', 'unknown'), ['woodshed_1.0.0_windows_amd64.msi', 'woodshed_1.0.0_windows_amd64.zip']);
  assert.deepEqual(p('macos', 'arm64'), ['woodshed_1.0.0_macos_universal.pkg', 'woodshed_1.0.0_darwin_universal.tar.gz']);
  assert.deepEqual(p('linux', 'x64'), ['woodshed_1.0.0_amd64.deb', 'woodshed-1.0.0-1.x86_64.rpm', 'woodshed_1.0.0_linux_amd64.tar.gz']);
  assert.deepEqual(p('linux', 'arm64'), ['woodshed_1.0.0_arm64.deb', 'woodshed-1.0.0-1.aarch64.rpm', 'woodshed_1.0.0_linux_arm64.tar.gz']);
  assert.deepEqual(p('unknown', 'unknown'), []);
});

test('"other downloads" lists everything else, and nothing is lost', () => {
  for (const platform of [{ os: 'windows', arch: 'x64' }, { os: 'linux', arch: 'arm64' }, { os: 'unknown', arch: 'unknown' }]) {
    const r = pick(RELEASE.assets, platform);
    assert.equal(r.best.length + r.others.length, NAMES.length - 1);
    assert.equal(r.checksums.name, 'checksums.txt');
  }
});

const LABELS = [
  'Windows installer (x64)',
  'Windows installer (ARM64)',
  'macOS installer (x64 and ARM64)',
  'Debian / Ubuntu package (x64)',
  'Debian / Ubuntu package (ARM64)',
  'Fedora / RHEL package (x64)',
  'Fedora / RHEL package (ARM64)',
  'Windows portable (x64)',
  'Windows portable (ARM64)',
  'macOS portable (x64 and ARM64)',
  'Linux portable (x64)',
  'Linux portable (ARM64)',
];

test('the same labels and picks for 1.0.0 and a prerelease (0.9.0-rc2)', () => {
  for (const X of ['1.0.0', '0.9.0-rc2']) {
    const names = namesFor(X);
    assert.deepEqual(names.slice(0, -1).map((n) => classify(n)?.label), LABELS, X);
    const rel = releaseFor(X);
    assert.deepEqual(pick(rel.assets, { os: 'linux', arch: 'arm64' }).best.map((a) => a.name), [
      `woodshed_${X}_arm64.deb`,
      `woodshed-${X}-1.aarch64.rpm`,
      `woodshed_${X}_linux_arm64.tar.gz`,
    ]);
    assert.deepEqual(pick(rel.assets, { os: 'windows', arch: 'x64' }).best.map((a) => a.name), [
      `woodshed_${X}_windows_amd64.msi`,
      `woodshed_${X}_windows_amd64.zip`,
    ]);
  }
});

test('the broken rc1 forms ("~", and GitHub\'s ".rc1" rename) still get the right label, never a wrong one', () => {
  const broken = {
    'woodshed_0.9.0~rc1_amd64.deb': 'Debian / Ubuntu package (x64)',
    'woodshed_0.9.0.rc1_amd64.deb': 'Debian / Ubuntu package (x64)',
    'woodshed_0.9.0~rc1_arm64.deb': 'Debian / Ubuntu package (ARM64)',
    'woodshed_0.9.0.rc1_arm64.deb': 'Debian / Ubuntu package (ARM64)',
    'woodshed-0.9.0~rc1-1.x86_64.rpm': 'Fedora / RHEL package (x64)',
    'woodshed-0.9.0.rc1-1.x86_64.rpm': 'Fedora / RHEL package (x64)',
    'woodshed-0.9.0~rc1-1.aarch64.rpm': 'Fedora / RHEL package (ARM64)',
    'woodshed-0.9.0.rc1-1.aarch64.rpm': 'Fedora / RHEL package (ARM64)',
    'woodshed_0.9.0.rc1_linux_amd64.tar.gz': 'Linux portable (x64)',
    'woodshed_0.9.0.rc1_windows_arm64.msi': 'Windows installer (ARM64)',
    'woodshed_0.9.0.rc1_macos_universal.pkg': 'macOS installer (x64 and ARM64)',
  };
  for (const [name, label] of Object.entries(broken)) assert.equal(classify(name)?.label, label, name);
  // Nothing that merely looks similar is offered: a deb/rpm without its arch, or other files.
  for (const name of ['woodshed_0.9.0~rc1.deb', 'woodshed-0.9.0.rc1.x86_64.rpm', 'woodshed_0.9.0.rc1_amd64.deb.sig', 'checksums.txt.rc1'])
    assert.equal(classify(name), null, name);
});

const nav = (userAgent, userAgentData) => ({ userAgent, userAgentData });

test('platform from user agents', async () => {
  const cases = [
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36', { os: 'windows', arch: 'x64' }],
    ['Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 Edg/140', { os: 'windows', arch: 'arm64' }],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15 Version/19 Safari/605.1.15', { os: 'macos', arch: 'unknown' }],
    ['Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0', { os: 'linux', arch: 'x64' }],
    ['Mozilla/5.0 (X11; Linux aarch64; rv:140.0) Gecko/20100101 Firefox/140.0', { os: 'linux', arch: 'arm64' }],
    ['Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/140 Mobile Safari/537.36', { os: 'unknown', arch: 'unknown' }],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148', { os: 'unknown', arch: 'unknown' }],
    ['Mozilla/5.0 (X11; CrOS x86_64 16000.0.0) AppleWebKit/537.36 Chrome/140', { os: 'unknown', arch: 'unknown' }],
  ];
  for (const [ua, want] of cases) assert.deepEqual(await detectPlatform(nav(ua)), want, ua);
});

test('userAgentData wins where the browser has it (Windows on ARM reports x64 in its UA)', async () => {
  const uad = (platform, architecture, mobile = false) => ({ platform, mobile, getHighEntropyValues: async () => ({ architecture, bitness: '64' }) });
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140';
  assert.deepEqual(await detectPlatform(nav(ua, uad('Windows', 'arm'))), { os: 'windows', arch: 'arm64' });
  assert.deepEqual(await detectPlatform(nav(ua, uad('macOS', 'arm'))), { os: 'macos', arch: 'arm64' });
  assert.deepEqual(await detectPlatform(nav(ua, uad('Android', 'arm', true))), { os: 'unknown', arch: 'unknown' });
  const denied = { platform: 'Linux', mobile: false, getHighEntropyValues: async () => { throw new Error('no'); } };
  assert.deepEqual(await detectPlatform(nav('Mozilla/5.0 (X11; Linux x86_64) Chrome/140', denied)), { os: 'linux', arch: 'x64' });
});

const res = (status, body) => ({ status, ok: status >= 200 && status < 300, json: async () => body });
const fileWith = (stable, prerelease) => async (url) => {
  assert.equal(url, RELEASES_FILE); // same origin: never the GitHub API
  return res(200, { generated_at: '2026-11-11T00:00:00Z', stable, prerelease });
};

test('releases.json with a stable release: offered as stable (a newer prerelease is ignored)', async () => {
  const r = await loadRelease(fileWith(releaseFor('1.0.0'), releaseFor('1.1.0-rc1')));
  assert.equal(r.ok, true);
  assert.equal(r.kind, 'stable');
  assert.equal(r.release.tag_name, 'v1.0.0');
});

test('releases.json with only a prerelease: offered as a release candidate', async () => {
  const r = await loadRelease(fileWith(null, releaseFor('0.9.0-rc2')));
  assert.equal(r.ok, true);
  assert.equal(r.kind, 'prerelease');
  assert.equal(r.release.tag_name, 'v0.9.0-rc2');
  assert.deepEqual(pick(r.release.assets, { os: 'macos', arch: 'arm64' }).best.map((a) => a.name), [
    'woodshed_0.9.0-rc2_macos_universal.pkg',
    'woodshed_0.9.0-rc2_darwin_universal.tar.gz',
  ]);
});

test('neither, or no usable files, or no file at all: the releases-page fallback', async () => {
  assert.deepEqual(await loadRelease(fileWith(null, null)), { ok: false, reason: 'none' });
  assert.deepEqual(await loadRelease(fileWith({ tag_name: 'v1.0.0', assets: [{ name: 'checksums.txt' }] }, null)), { ok: false, reason: 'none' });
  assert.deepEqual(await loadRelease(async () => res(404, {})), { ok: false, reason: 'missing' });
  assert.deepEqual(await loadRelease(async () => res(500, {})), { ok: false, reason: 'error' });
  assert.deepEqual(await loadRelease(async () => { throw new TypeError('Failed to fetch'); }), { ok: false, reason: 'error' });
  assert.deepEqual(await loadRelease(async () => ({ status: 200, ok: true, json: async () => { throw new SyntaxError('bad'); } })), { ok: false, reason: 'error' });
});

test('releases.json is built from the API: latest stable and latest prerelease, no drafts, only the fields used', () => {
  const api = (tag, published_at, extra = {}) => ({
    tag_name: tag,
    name: `Woodshed ${tag}`,
    html_url: `https://github.com/gmccollu/woodshed/releases/tag/${tag}`,
    published_at,
    draft: false,
    prerelease: tag.includes('-'),
    body: 'long notes',
    author: { login: 'someone' },
    assets: [{ name: `woodshed_${tag.slice(1)}_amd64.deb`, size: 5, browser_download_url: 'https://x/y', digest: 'sha256:ab', uploader: {}, id: 1 }],
    ...extra,
  });
  // --slurp gives an array of pages
  const pages = [
    [api('v0.9.0-rc1', '2026-11-01T00:00:00Z'), api('v0.9.0-rc2', '2026-11-08T00:00:00Z')],
    [api('v1.0.0', '2026-11-20T00:00:00Z', { draft: true, published_at: null }), api('v0.8.0', '2026-10-01T00:00:00Z')],
  ];
  const out = summarize(pages, new Date('2026-11-11T00:00:00Z'));
  assert.equal(out.generated_at, '2026-11-11T00:00:00.000Z');
  assert.equal(out.stable.tag_name, 'v0.8.0');
  assert.equal(out.prerelease.tag_name, 'v0.9.0-rc2');
  assert.deepEqual(Object.keys(out.prerelease).sort(), ['assets', 'html_url', 'name', 'published_at', 'tag_name']);
  assert.deepEqual(out.prerelease.assets[0], { name: 'woodshed_0.9.0-rc2_amd64.deb', size: 5, browser_download_url: 'https://x/y', digest: 'sha256:ab' });
  assert.deepEqual(summarize([], new Date(0)), { generated_at: '1970-01-01T00:00:00.000Z', stable: null, prerelease: null });
});

test('one constant names the repository', () => {
  assert.equal(releasesUrl(), `https://github.com/${REPO.owner}/${REPO.name}/releases`);
  assert.equal(RELEASES_FILE, './releases.json');
});

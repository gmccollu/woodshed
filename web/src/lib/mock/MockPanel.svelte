<script lang="ts">
  import { MOCK_PASSWORD, expireSession, expireSummaries, mock, restartFirstRun, sendFirstMessage, setFleetSize, setLanAuth, updates } from './server.svelte';
  import { loadSession } from '../session.svelte';
  import { live, refreshDevices, refreshStatus } from '../status.svelte';
  import { go } from '../router.svelte';

  let open = $state(false);

  function toggle(key: 'clash' | 'paused' | 'cycle' | 'queueFull') {
    mock[key] = !mock[key];
    refreshStatus();
  }
  function firstRun() {
    restartFirstRun();
    refreshDevices();
    go('welcome');
  }
  async function lan() {
    setLanAuth(!mock.lan);
    await loadSession();
    refreshStatus();
  }
  function expire() {
    expireSession();
    refreshStatus(); // gets a 401, which shows the login form
  }
  // TLS state (mock_tls) lives in the URL, so switching it reloads the mock from scratch.
  const tlsMode = new URLSearchParams(location.search).get('mock_tls') ?? 'on';
  function setTlsMode(v: string) {
    const u = new URL(location.href);
    if (v === 'on') u.searchParams.delete('mock_tls');
    else u.searchParams.set('mock_tls', v);
    location.href = u.toString();
  }
  const windows = $derived((live.status?.os ?? '').startsWith('windows'));
  function tlsToggle(key: 'tlsExpiring' | 'tlsNames') {
    mock[key] = !mock[key];
    refreshStatus();
  }

  function testMessage() {
    sendFirstMessage();
    refreshDevices();
  }
</script>

{#if mock.panel}
  <div class="mock-panel" role="region" aria-label="Mock controls">
    <button class="mock-toggle" onclick={() => (open = !open)} aria-expanded={open}>
      Mock data {open ? '▾' : '▸'}
    </button>
    {#if open}
      <div class="mock-body">
        <label class="row">
          <span>Rate (msg/s)</span>
          <input type="number" min="0" step="1" bind:value={mock.rate} class="field" />
        </label>
        <div class="row presets">
          {#each [5, 40, 1284, 10000] as r (r)}
            <button class="ghost-btn" onclick={() => (mock.rate = r)}>{r.toLocaleString()}</button>
          {/each}
        </div>
        <label class="row"><input type="checkbox" checked={mock.clash} onchange={() => toggle('clash')} /> TCP 514 port clash</label>
        <label class="row"><input type="checkbox" checked={mock.paused} onchange={() => toggle('paused')} /> Writes paused (low disk)</label>
        <label class="row"><input type="checkbox" checked={mock.queueFull} onchange={() => toggle('queueFull')} /> UDP queue full (disk fell behind)</label>
        <label class="row"><input type="checkbox" checked={mock.cycle} onchange={() => toggle('cycle')} /> Cycle branch-ap-08 quiet/offline</label>
        <label class="row">
          <span>Latency (ms)</span>
          <input type="number" min="0" step="10" bind:value={mock.latency} class="field" />
        </label>
        <div class="row presets">
          <button class="ghost-btn" onclick={firstRun}>Restart as first run</button>
          <button class="ghost-btn" onclick={testMessage} disabled={!mock.firstRun}>Send test message</button>
        </div>
        <label class="row">
          <input type="checkbox" checked={mock.fleetExtra > 0} onchange={(e) => { setFleetSize(e.currentTarget.checked ? 10_000 : 0); refreshDevices(); }} />
          10,000 extra devices
        </label>
        <label class="row"><input type="checkbox" bind:checked={mock.deviceLimit} onchange={() => refreshStatus()} /> New senders refused (device limit)</label>
        <label class="row"><input type="checkbox" bind:checked={mock.slowScan} /> Slow search scans (partial pages)</label>
        <label class="row"><input type="checkbox" bind:checked={mock.slowSummary} /> Slow field counts (partial summaries)</label>
        <button class="ghost-btn" onclick={expireSummaries}>Expire running field counts</button>
        <label class="row"><input type="checkbox" bind:checked={mock.exportFail} /> Exports fail at 40 %</label>
        <label class="row"><input type="checkbox" checked={mock.lan} onchange={lan} /> LAN mode with auth</label>
        <label class="row">
          Update checks find
          <select class="field" bind:value={updates.result}>
            <option value="newer">1.2.0 is out</option>
            <option value="latest">this is the latest</option>
            <option value="error">a TLS error</option>
          </select>
        </label>
        <div class="row presets">
          <button class="ghost-btn" onclick={expire} disabled={!mock.lan || !mock.loggedIn}>Expire session</button>
        </div>
        <label class="row">
          <span>TLS listener</span>
          <select class="field" value={tlsMode} onchange={(e) => setTlsMode(e.currentTarget.value)}>
            <option value="on">On (own CA)</option>
            <option value="off">Off (cert kept)</option>
            <option value="never">Never turned on</option>
            <option value="file">On (your cert file)</option>
          </select>
        </label>
        <label class="row"><input type="checkbox" checked={mock.tlsExpiring} onchange={() => tlsToggle('tlsExpiring')} /> TLS cert expires soon</label>
        <label class="row"><input type="checkbox" checked={mock.tlsNames} onchange={() => tlsToggle('tlsNames')} /> Host name not in TLS cert</label>
        <label class="row" title={windows ? '' : 'Start the mock with mock_os=windows'}>
          <input
            type="checkbox"
            disabled={!windows}
            checked={mock.tlsFirewall !== 'ok'}
            onchange={(e) => {
              mock.tlsFirewall = e.currentTarget.checked ? 'disabled' : 'ok';
              refreshStatus();
            }}
          />
          TLS firewall rule off (Windows)
        </label>
        <p class="hint">TLS 1.0/1.1 banner: tick "Allow TLS 1.0 and 1.1" in Settings and save.</p>
        <p class="hint">Mock password: <code>{MOCK_PASSWORD}</code>. Ten wrong tries lock logins for 15 min.</p>
        <p class="hint">Settings validation: try port 70000, a bad CIDR, or offline &lt; quiet.</p>
        <p class="hint">The update check needs <code>?mock_updates=ask</code> (or on, off): a release build.</p>
      </div>
    {/if}
  </div>
{/if}

<style>
  .mock-panel {
    position: fixed;
    right: 16px;
    bottom: 16px;
    z-index: 50;
    width: 260px;
    font-size: 13px;
    color: var(--fg);
    background: var(--glass-strong);
    border: 1px dashed var(--muted);
    border-radius: 16px;
    padding: 8px;
    backdrop-filter: blur(16px);
    box-shadow: var(--shadow);
  }
  .mock-toggle {
    width: 100%;
    text-align: left;
    background: none;
    border: 0;
    color: var(--fg);
    font-weight: 600;
    cursor: pointer;
    padding: 4px 6px;
  }
  .mock-body {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 6px;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .row span {
    flex: 1;
  }
  .row .field {
    width: 100px;
    padding: 4px 8px;
  }
  .presets {
    flex-wrap: wrap;
    gap: 6px;
  }
  .presets :global(.ghost-btn) {
    padding: 3px 9px;
    font-size: 12px;
  }
  .hint {
    margin: 0;
    color: var(--muted);
    font-size: 12px;
  }
</style>

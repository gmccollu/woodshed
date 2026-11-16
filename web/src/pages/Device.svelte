<script lang="ts">
  // One device's page (1.3, #/device?id=10.1.0.1&r=24h): who it is, links to its lines in Events,
  // and the Polling panel (SPEC §12.5) when it's polled, or "Add polling" when it isn't. Reached
  // from the Devices page (the Polled column and the Polled list).
  import { getDevices, getPollTargets, type Device } from '../lib/api';
  import { ago, dateTime, num } from '../lib/format';
  import { router, setQuery } from '../lib/router.svelte';
  import { live, remember } from '../lib/status.svelte';
  import { prefs } from '../lib/prefs.svelte';
  import { openPollForm, pollUi } from '../lib/pollui.svelte';
  import type { PollTarget } from '../lib/poll';
  import PollPanel from '../components/PollPanel.svelte';
  import StatusDot from '../components/StatusDot.svelte';

  const RANGES = [
    { r: '1h', label: '1 h', ms: 3_600_000 },
    { r: '6h', label: '6 h', ms: 6 * 3_600_000 },
    { r: '24h', label: '24 h', ms: 86_400_000 },
    { r: '7d', label: '7 d', ms: 7 * 86_400_000 },
    { r: '30d', label: '30 d', ms: 30 * 86_400_000 },
  ];
  const q = $derived(new URLSearchParams(router.query));
  const id = $derived(q.get('id') ?? '');
  const rk = $derived(RANGES.some((x) => x.r === q.get('r')) ? q.get('r')! : '24h');
  // Quick ranges end at now rounded up to the minute, as Events' do, and move on every minute.
  let minute = $state(Math.ceil(Date.now() / 60_000));
  $effect(() => {
    const t = setInterval(() => (minute = Math.ceil(Date.now() / 60_000)), 15_000);
    return () => clearInterval(t);
  });
  const to = $derived(new Date(minute * 60_000).toISOString());
  const from = $derived(new Date(minute * 60_000 - RANGES.find((x) => x.r === rk)!.ms).toISOString());
  function setRange(r: string) {
    const p = new URLSearchParams(router.query);
    p.set('r', r);
    setQuery(p.toString());
  }

  let device = $state<Device | null | undefined>(undefined);
  let target = $state<PollTarget | null | undefined>(undefined);
  let loadError = $state('');
  $effect(() => {
    const want = id;
    void pollUi.version;
    if (!want) return;
    Promise.all([getDevices({ q: want, limit: 50, hidden: 'include' }), getPollTargets()]).then(
      ([page, ts]) => {
        remember(page.devices);
        device = page.devices.find((d) => d.id === want) ?? null;
        target = ts.find((t) => t.device_id === want) ?? null;
        loadError = '';
      },
      (e) => (loadError = (e as Error).message),
    );
  });
  const title = $derived(device?.name || target?.state.sys_name || id);
</script>

{#if !id}
  <section class="card"><p class="m-0">No device chosen. <a class="text-link underline" href="#/devices">Open Devices</a> and pick one.</p></section>
{:else}
  <div class="space-y-4">
    <section class="card">
      <a class="text-link text-[13px] underline" href="#/devices">← Devices</a>
      <div class="mt-2 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 class="m-0 text-xl font-bold tracking-tight">{title}</h1>
          <p class="mt-1 mb-0 text-[13.5px] text-muted">
            <span class="font-mono">{id}</span>
            {#if device}
              · <StatusDot status={device.status} label />
              {#if device.group}· group {device.group}{/if}
              · last heard <span title={dateTime(device.last_heard)}>{ago(device.last_heard, live.now)}</span>
              · {num(device.total_msgs)} lines stored
            {:else if device === null}
              · not a device yet{target ? ': it becomes one on its first answer to a poll' : ''}
            {/if}
          </p>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          {#if device}
            <a class="ghost-btn" href="#/events?dev={encodeURIComponent(id)}&r=24h">Syslog in Events</a>
            {#if device.types?.includes('trap')}<a class="ghost-btn" href="#/events?type=trap&dev={encodeURIComponent(id)}&r=24h">SNMP traps</a>{/if}
          {/if}
        </div>
      </div>
      {#if loadError}<p class="mb-0 text-bad-fg" role="alert">{loadError}</p>{/if}
    </section>

    {#if target}
      <div class="flex flex-wrap items-center gap-3">
        <div class="seg" role="radiogroup" aria-label="Range">
          {#each RANGES as r (r.r)}
            <button role="radio" aria-checked={rk === r.r} onclick={() => setRange(r.r)}>{r.label}</button>
          {/each}
        </div>
        <span class="text-[13px] text-muted">Times in {prefs.utc ? 'UTC' : 'local time'}.</span>
      </div>
      {#key pollUi.version}
        <PollPanel device={id} {from} {to} utc={prefs.utc} onedit={(t) => openPollForm(t)} />
      {/key}
    {:else if target === null}
      <section class="card">
        <h2 class="m-0 text-[17px] font-bold">Polling</h2>
        <p class="hint">
          This device isn't polled. Polling asks it every minute for its uptime, interface traffic and errors, and CPU and memory where it has
          them, and graphs them beside its logs with reboots marked. Woodshed sends SNMP requests only to the devices you add.
        </p>
        <button class="pill-btn" onclick={() => openPollForm(null, device?.ip ?? id, id)}>Add polling</button>
      </section>
    {/if}
  </div>
{/if}

<style>
  .hint {
    font-size: 13.5px;
    color: var(--muted);
  }
  .seg {
    display: inline-flex;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 3px;
  }
  .seg button {
    border: 0;
    background: transparent;
    color: var(--fg);
    padding: 5px 12px;
    border-radius: 999px;
    font-size: 13px;
    cursor: pointer;
  }
  .seg button[aria-checked='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
</style>

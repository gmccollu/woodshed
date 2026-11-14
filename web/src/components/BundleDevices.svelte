<script lang="ts">
  // The bundle preview's device list (SPEC §11.3): the devices with a stored record of any type in
  // the window (GET /api/devices?active_from&active_to&hidden=exclude), each with its counts per
  // type in the window (GET /api/search/summary, fields=device). Unchecking one turns "every
  // active device" (or the group) into the list of the rest; devices chosen by name stay listed
  // even when they sent nothing in the window.
  import { getDevices, getSummary, type DataType, type Device } from '../lib/api';
  import { checkDevice, uncheckDevice, type BundleForm, type BundleWindow } from '../lib/bundle';
  import { num } from '../lib/format';
  import { allScope } from '../lib/scope';
  import { deviceName, knownDevice, remember } from '../lib/status.svelte';
  import DevicePicker from './DevicePicker.svelte';

  let {
    value = $bindable(),
    win,
    types,
    listed = $bindable([]),
  }: {
    value: BundleForm;
    win: BundleWindow | null;
    /** The types to count (the bundle's, or every type the server has). */
    types: DataType[];
    /** The ids of the active devices listed, for the page's own "leave this device out". */
    listed?: string[];
  } = $props();

  const LIMIT = 1000;
  let devices = $state.raw<Device[]>([]);
  let total = $state(0);
  let loading = $state(false);
  let error = $state('');

  // Which devices to list: the active ones, of the group (or the ungrouped ones) when that's the choice.
  // Kept as strings, so checking a box (a new scope, the same window) doesn't fetch the list again.
  const listKey = $derived(value.scope.mode === 'group' ? `g:${value.scope.group}` : value.scope.mode === 'ungrouped' ? 'u' : '');
  const wFrom = $derived(win?.from ?? '');
  const wTo = $derived(win?.to ?? '');
  const scopeOf = (k: string): { group?: string; ungrouped?: boolean } => (k.startsWith('g:') ? { group: k.slice(2) } : k === 'u' ? { ungrouped: true } : {});

  $effect(() => {
    if (!wFrom) {
      devices = [];
      total = 0;
      return;
    }
    const p = { active_from: wFrom, active_to: wTo, hidden: 'exclude' as const, sort: 'name' as const, limit: LIMIT, ...scopeOf(listKey) };
    const ctrl = new AbortController();
    loading = true;
    getDevices(p, ctrl.signal)
      .then((page) => {
        remember(page.devices);
        devices = page.devices;
        total = page.total;
        listed = page.devices.map((d) => d.id);
        error = '';
      })
      .catch((x) => {
        if ((x as Error).name !== 'AbortError') error = (x as Error).message;
      })
      .finally(() => (loading = false));
    return () => ctrl.abort();
  });

  // Counts in the window, per type: the summary's device field (its top 50 per type).
  let counts = $state.raw<Record<string, Map<string, number>>>({});
  let partial = $state(false);
  const typeKey = $derived(types.map((t) => t.type).join(','));
  $effect(() => {
    if (!wFrom) return;
    const ctrl = new AbortController();
    const base = { q: '', from: wFrom, to: wTo, ...scopeOf(listKey), fields: ['device'], histogram: false, top: 50 };
    const want = typeKey.split(',').filter(Boolean);
    Promise.all(
      want.map((t) =>
        getSummary({ ...base, type: t === 'syslog' ? undefined : t }, ctrl.signal)
          .then((s) => ({ t, s }))
          .catch(() => null),
      ),
    ).then((all) => {
      if (ctrl.signal.aborted) return;
      const out: Record<string, Map<string, number>> = {};
      let part = false;
      for (const r of all) {
        if (!r) continue;
        part ||= r.s.partial;
        out[r.t] = new Map((r.s.fields.find((f) => f.key === 'device')?.values ?? []).map((v) => [v.value, v.count]));
      }
      counts = out;
      partial = part;
    });
    return () => ctrl.abort();
  });

  // Chosen devices that aren't in the active list: silent in the window, hidden, or past the first 1,000.
  const extra = $derived(value.scope.mode === 'devices' ? value.scope.devices.filter((id) => !devices.some((d) => d.id === id)) : []);
  const checked = (id: string) => value.scope.mode !== 'devices' || value.scope.devices.includes(id);
  const ids = $derived(devices.map((d) => d.id));
  function toggle(id: string) {
    value.scope = checked(id) ? uncheckDevice(value.scope, ids, id) : checkDevice(value.scope, ids, id);
  }
  const nChecked = $derived(value.scope.mode === 'devices' ? value.scope.devices.length : total);

  const TYPE_SHORT: Record<string, string> = { syslog: 'syslog', trap: 'traps' };
  function countText(id: string): string {
    const bits: string[] = [];
    for (const t of types) {
      const n = counts[t.type]?.get(id);
      if (n) bits.push(`${num(n)} ${t.type === 'trap' && n === 1 ? 'trap' : (TYPE_SHORT[t.type] ?? t.label)}`);
    }
    return bits.join(' · ');
  }
</script>

<div class="bd">
  <div class="head">
    <b class="text-[14px]">Devices</b>
    <DevicePicker bind:value={value.scope} allLabel="Every device active in the window" />
    {#if value.scope.mode === 'devices'}
      <button type="button" class="ghost-btn" onclick={() => (value.scope = allScope())} title="Back to every device that stored anything in the window">Every active device</button>
    {/if}
  </div>
  <p class="m-0 text-[12.5px] text-muted" aria-live="polite">
    {#if error}<span class="text-bad-fg font-medium" role="alert">{error}</span>
    {:else if loading && !devices.length}Finding the devices active in the window…
    {:else if !win}—
    {:else}
      {num(nChecked)} of {num(total + extra.length)} checked{value.scope.mode === 'group' ? ` (group ${value.scope.group})` : value.scope.mode === 'ungrouped' ? ' (ungrouped)' : ''}.
      {total > devices.length ? `Showing the first ${num(devices.length)} active.` : ''}
      Uncheck a device to leave it out.{partial ? ' Counts so far.' : ''}
    {/if}
  </p>
  <ul class="list" aria-label="Devices in the bundle">
    {#each devices as d (d.id)}
      <li>
        <label class="dev" class:off={!checked(d.id)}>
          <input type="checkbox" checked={checked(d.id)} onchange={() => toggle(d.id)} />
          <span class="nm truncate">{d.name || d.ip}</span>
          <span class="ip font-mono">{d.name ? d.ip : ''}</span>
          <span class="grp">{d.group}</span>
          <span class="cnt">{countText(d.id)}</span>
        </label>
      </li>
    {/each}
    {#each extra as id (id)}
      <li>
        <label class="dev" class:off={!checked(id)}>
          <input type="checkbox" checked={checked(id)} onchange={() => toggle(id)} />
          <span class="nm truncate">{deviceName(id)}</span>
          <span class="ip font-mono">{deviceName(id) !== id ? id : ''}</span>
          <span class="grp">{knownDevice(id)?.group ?? ''}</span>
          <span class="cnt text-muted">{countText(id) || `nothing in the window${knownDevice(id)?.hidden ? ' · hidden' : ''}`}</span>
        </label>
      </li>
    {/each}
    {#if win && !loading && !devices.length && !extra.length && !error}
      <li class="none">No device stored anything in this window.</li>
    {/if}
  </ul>
</div>

<style>
  .bd {
    display: flex;
    flex-direction: column;
    gap: 6px;
    min-width: 0;
  }
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 10px;
  }
  .list {
    margin: 0;
    padding: 4px;
    list-style: none;
    max-height: 290px;
    overflow: auto;
    border-radius: 14px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
  }
  .dev {
    display: grid;
    grid-template-columns: auto minmax(6rem, 1fr) auto auto;
    grid-template-areas: 'cb nm ip grp' 'cb cnt cnt cnt';
    align-items: center;
    column-gap: 10px;
    padding: 5px 8px;
    border-radius: 10px;
    font-size: 13.5px;
    cursor: pointer;
  }
  .dev:hover {
    background: var(--glass);
  }
  .dev input {
    grid-area: cb;
  }
  .nm {
    grid-area: nm;
    font-weight: 600;
    min-width: 0;
  }
  .ip {
    grid-area: ip;
    font-size: 12px;
    color: var(--muted);
  }
  .grp {
    grid-area: grp;
    font-size: 12px;
    color: var(--muted);
  }
  .cnt {
    grid-area: cnt;
    font-size: 12.5px;
  }
  .dev.off .nm,
  .dev.off .cnt {
    color: var(--muted);
    text-decoration: line-through;
  }
  .none {
    padding: 10px;
    font-size: 13.5px;
    color: var(--muted);
  }
</style>

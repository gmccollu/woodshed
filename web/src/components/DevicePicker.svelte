<script lang="ts">
  // Scope picker for search and export. The device list comes from the server as you
  // type (/api/devices?q=…), so it stays fast with 10,000 devices.
  import { getDevices, type Device } from '../lib/api';
  import { scopeLabel, type Scope } from '../lib/scope';
  import { anyUngrouped, groupsSeen, remember } from '../lib/status.svelte';
  import StatusDot from './StatusDot.svelte';

  let {
    value = $bindable(),
    allowGroups = true,
    allLabel = 'All devices',
  }: { value: Scope; allowGroups?: boolean; /** What "all" means here (the bundle: every device active in the window). */ allLabel?: string } = $props();

  const LIST = 100;
  let open = $state(false);
  let filter = $state('');
  let root: HTMLDivElement | undefined = $state();
  let listed = $state<Device[]>([]);
  let total = $state(0);
  let loading = $state(false);

  const groups = $derived(open ? groupsSeen() : []);
  const hasUngrouped = $derived(open && anyUngrouped());

  $effect(() => {
    if (!open) return;
    const f = filter.trim();
    const ctrl = new AbortController();
    const t = setTimeout(async () => {
      loading = true;
      try {
        const page = await getDevices({ q: f, sort: 'name', limit: LIST, hidden: 'include' }, ctrl.signal);
        remember(page.devices);
        listed = page.devices;
        total = page.total;
      } catch {
        /* keep the last list */
      } finally {
        loading = false;
      }
    }, f ? 250 : 0);
    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  });

  $effect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (root && !root.contains(e.target as Node)) open = false;
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') open = false;
    };
    addEventListener('mousedown', close);
    addEventListener('keydown', esc);
    return () => {
      removeEventListener('mousedown', close);
      removeEventListener('keydown', esc);
    };
  });

  function toggle(id: string) {
    const cur = value.mode === 'devices' ? value.devices : [];
    value = { mode: 'devices', group: '', devices: cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id] };
  }
</script>

<div class="dp" bind:this={root}>
  <button type="button" class="ghost-btn trigger" aria-expanded={open} aria-haspopup="dialog" onclick={() => (open = !open)}>
    <span class="truncate">{value.mode === 'all' ? allLabel : scopeLabel(value)}</span> <span aria-hidden="true">▾</span>
  </button>
  {#if open}
    <div class="pop glass" role="dialog" aria-label="Choose devices">
      {#if allowGroups}
        <div class="opts" role="radiogroup" aria-label="Scope">
          <label><input type="radio" checked={value.mode === 'all'} onchange={() => (value = { mode: 'all', group: '', devices: [] })} /> {allLabel}</label>
          {#each groups as g (g)}
            <label><input type="radio" checked={value.mode === 'group' && value.group === g} onchange={() => (value = { mode: 'group', group: g, devices: [] })} /> Group: {g}</label>
          {/each}
          {#if hasUngrouped}
            <label><input type="radio" checked={value.mode === 'ungrouped'} onchange={() => (value = { mode: 'ungrouped', group: '', devices: [] })} /> Ungrouped</label>
          {/if}
        </div>
      {/if}
      <input class="field my-2" placeholder="Find a device by name or IP" bind:value={filter} aria-label="Find a device" />
      <p class="m-0 mb-1 text-[12px] text-muted" aria-live="polite">
        {loading ? 'Searching…' : total > listed.length ? `Showing ${listed.length} of ${total.toLocaleString()}. Type to narrow.` : `${total.toLocaleString()} device${total === 1 ? '' : 's'}`}
      </p>
      <div class="list">
        {#each listed as d (d.id)}
          <label class="dev">
            <input type="checkbox" checked={value.mode === 'devices' && value.devices.includes(d.id)} onchange={() => toggle(d.id)} />
            <StatusDot status={d.status} />
            <span class="truncate font-medium">{d.name || d.ip}</span>
            <span class="text-muted ml-auto font-mono text-[12px]">{d.name ? d.ip : ''}{d.hidden ? ' · hidden' : ''}</span>
          </label>
        {/each}
      </div>
      <div class="mt-2 flex gap-2">
        <button
          type="button"
          class="ghost-btn"
          onclick={() => (value = { mode: 'devices', group: '', devices: listed.filter((d) => !d.hidden).map((d) => d.id) })}>Select shown</button
        >
        <button type="button" class="ghost-btn" onclick={() => (value = { mode: 'devices', group: '', devices: [] })}>Clear</button>
        <button type="button" class="pill-btn ml-auto" onclick={() => (open = false)}>Done</button>
      </div>
    </div>
  {/if}
</div>

<style>
  .dp {
    position: relative;
  }
  .trigger {
    max-width: 320px;
    padding: 7px 14px;
  }
  .pop {
    position: absolute;
    z-index: 30;
    top: calc(100% + 6px);
    left: 0;
    width: 360px;
    padding: 12px;
    border-radius: 18px;
    background: var(--glass-strong);
    box-shadow: var(--shadow);
  }
  .opts {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 14px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--divider);
  }
  .list {
    max-height: 260px;
    overflow: auto;
    display: flex;
    flex-direction: column;
  }
  .dev {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 4px;
    font-size: 14px;
    border-radius: 8px;
    min-width: 0;
  }
  .dev:hover {
    background: var(--glass);
  }
</style>

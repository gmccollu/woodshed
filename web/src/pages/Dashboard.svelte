<script lang="ts">
  import { getDevices, getStats, type Device, type Stats } from '../lib/api';
  import { ago, agoShort, approxDays, bytes, num, num1, rate } from '../lib/format';
  import { anyUngrouped, deviceName, DEVICE_POLL_MS, groupsSeen, live, NOW_WITHIN_S, remember } from '../lib/status.svelte';
  import { ui } from '../lib/ui.svelte';
  import { prefs } from '../lib/prefs.svelte';
  import { eventsQueryFor } from '../lib/fields';
  import { href } from '../lib/router.svelte';
  import LiveTail from '../components/LiveTail.svelte';
  import Sparkline from '../components/Sparkline.svelte';
  import StatusDot from '../components/StatusDot.svelte';
  import { blockUi, openMenu } from '../lib/block.svelte';
  import Icon from '../components/Icon.svelte';

  const ALL = '\u0000all';
  const UNGROUPED = '\u0000none';
  /** Chips shown in the strip before "All N devices". */
  const STRIP_MAX = 30;

  let stats = $state<Stats | null>(null);
  let statsError = $state('');
  let tab = $state(ALL);
  let picked = $state<string[]>([]);

  async function load() {
    try {
      stats = await getStats();
      statsError = '';
    } catch (e) {
      statsError = (e as Error).message;
    }
  }

  $effect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  });

  const groups = $derived(live.devices ? groupsSeen() : []);
  const hasUngrouped = $derived(live.devices ? anyUngrouped() : false);
  const filterText = $derived(ui.filter.trim());

  // The strip asks the server for the busiest STRIP_MAX in the current tab and filter,
  // plus the total (docs/api.md: sort=rate is busiest first).
  let strip = $state<Device[] | null>(null);
  let stripTotal = $state(0);
  // Blocked devices are left out unless asked for; N comes from the server.
  let showBlocked = $state(false);
  let blockedCount = $state(0);
  $effect(() => {
    void blockUi.version; // a block or unblock reloads the strip at once
    const p = {
      sort: 'rate' as const,
      limit: STRIP_MAX,
      hidden: 'exclude' as const,
      blocked: showBlocked ? ('include' as const) : ('exclude' as const),
      q: filterText,
      group: tab !== ALL && tab !== UNGROUPED ? tab : undefined,
      ungrouped: tab === UNGROUPED,
    };
    let stop = false;
    const ctrl = new AbortController();
    const loadStrip = async () => {
      try {
        const [page, blk] = await Promise.all([
          getDevices(p, ctrl.signal),
          getDevices({ blocked: 'only', hidden: 'exclude', limit: 1 }, ctrl.signal),
        ]);
        if (stop) return;
        remember(page.devices);
        // The server filters by blocked; checking here too keeps a server that ignores the
        // parameter from showing blocked devices by default.
        strip = showBlocked ? page.devices : page.devices.filter((d) => !d.blocked);
        stripTotal = page.total;
        blockedCount = blk.devices.length ? blk.total : 0;
      } catch {
        /* keep the last strip */
      }
    };
    const t0 = setTimeout(loadStrip, filterText ? 250 : 0);
    const t = setInterval(loadStrip, DEVICE_POLL_MS);
    return () => {
      stop = true;
      ctrl.abort();
      clearTimeout(t0);
      clearInterval(t);
    };
  });

  const label = (d: Device) => d.name || d.ip;
  // Busiest first. Rates are bucketed (powers of two) so chips don't swap places every poll.
  const bucket = (d: Device) => Math.round(Math.log2(d.msgs_per_min + 1));
  const chips = $derived(
    [...(strip ?? [])].sort((a, b) => bucket(b) - bucket(a) || label(a).localeCompare(label(b), undefined, { numeric: true })),
  );

  // Click selects one device (click it again to clear); Cmd/Ctrl-click adds or removes.
  function pick(id: string, e: MouseEvent) {
    if (e.metaKey || e.ctrlKey) picked = picked.includes(id) ? picked.filter((x) => x !== id) : [...picked, id];
    else picked = picked.length === 1 && picked[0] === id ? [] : [id];
  }

  const tailDevices = $derived(picked);
  const tailUngrouped = $derived(!picked.length && tab === UNGROUPED);
  const tailGroup = $derived(picked.length || tab === ALL || tab === UNGROUPED ? '' : tab);
  const scope = $derived.by(() => {
    if (picked.length) {
      const names = picked.map(deviceName);
      return names.length > 3 ? `${names.slice(0, 3).join(', ')} +${names.length - 3}` : names.join(', ');
    }
    return tab === ALL ? 'all devices' : tab === UNGROUPED ? 'ungrouped' : tab;
  });

  // "Open in Events": the same devices (or group), severities and text over the last hour.
  const eventsHref = $derived(
    `${href('events')}?${eventsQueryFor({ devices: tailDevices, group: tailGroup, ungrouped: tailUngrouped, severities: prefs.tailSev, q: ui.filter })}`,
  );

  function setTab(t: string) {
    tab = t;
    picked = [];
  }

  // The tail fills the rest of the window, with a sensible minimum.
  let tailBox: HTMLDivElement | undefined = $state();
  let tailHeight = $state(560);
  $effect(() => {
    const fit = () => {
      if (!tailBox) return;
      const top = tailBox.getBoundingClientRect().top + scrollY;
      tailHeight = Math.max(380, Math.round(innerHeight - top - 76));
    };
    fit();
    addEventListener('resize', fit);
    const t = setInterval(fit, 1000);
    return () => {
      removeEventListener('resize', fit);
      clearInterval(t);
    };
  });

  // How the "≈ N days of history" estimate is made (docs/api.md → retention estimate).
  const estimateTip = $derived.by(() => {
    const d = stats?.disk;
    if (!d || d.estimated_days === null || d.bytes_per_day === null) return '';
    const ratio = d.compression_ratio ? `${num1(d.compression_ratio)}×` : 'about 8×';
    return (
      `Estimated from the last 24 h of intake (${bytes(d.bytes_per_day)} a day on disk), the compression measured on this machine's ` +
      `closed files (${ratio}), the ${bytes(d.cap_bytes)} size cap and the age limit. Whichever is reached first decides how long logs are kept.`
    );
  });
  const diskPct = $derived(stats ? Math.min(100, (stats.disk.used_bytes / Math.max(1, stats.disk.cap_bytes)) * 100) : 0);
  const osName = $derived(
    live.status?.os.startsWith('darwin') ? 'macOS' : live.status?.os.startsWith('windows') ? 'Windows' : 'this OS',
  );
</script>

{#if statsError && !live.statusError}
  <p class="mb-3 text-sm text-bad-fg" role="alert">Couldn't load stats: {statsError}</p>
{/if}

<div class="mb-4 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
  <div class="card">
    <h2 class="card-title">Messages / sec</h2>
    <div class="big">{stats ? num(stats.msgs_per_sec) : '—'}</div>
    <Sparkline values={stats?.sparkline ?? []} />
    <p class="sub">Last hour, per minute</p>
  </div>
  <div class="card">
    <h2 class="card-title">Devices</h2>
    <div class="big">{stats ? num(stats.devices.total) : '—'}</div>
    {#if stats}
      <p class="sub flex flex-wrap gap-x-3">
        <span class="inline-flex items-center gap-1.5"><StatusDot status="online" />{stats.devices.online} online</span>
        <span class="inline-flex items-center gap-1.5"><StatusDot status="quiet" />{stats.devices.quiet} quiet</span>
        <span class="inline-flex items-center gap-1.5"><StatusDot status="offline" />{stats.devices.offline} offline</span>
      </p>
    {/if}
  </div>
  <div class="card">
    <h2 class="card-title">Disk used</h2>
    <div class="big">
      {stats ? bytes(stats.disk.used_bytes).split(' ')[0] : '—'}
      {#if stats}<small>{bytes(stats.disk.used_bytes).split(' ')[1]}</small>{/if}
    </div>
    <div
      class="mt-2 h-2 overflow-hidden rounded-full bg-black/10 dark:bg-white/10"
      role="progressbar"
      aria-label="Disk used against the cap"
      aria-valuenow={Math.round(diskPct)}
      aria-valuemin={0}
      aria-valuemax={100}
    >
      <i class="block h-full rounded-full bg-accent" style:width="{Math.max(diskPct, stats ? 1.5 : 0)}%"></i>
    </div>
    {#if stats}
      <p class="sub" title="{bytes(stats.disk.free_bytes)} free on the data volume">of {bytes(stats.disk.cap_bytes)} · {stats.disk.days_kept} {stats.disk.days_kept === 1 ? 'day' : 'days'} kept</p>
      {#if stats.disk.estimated_days !== null}
        <p class="sub est" title={estimateTip}>
          {approxDays(stats.disk.estimated_days)} of history at the current rate
          <span class="sr-only">. {estimateTip}</span>
          {#if stats.disk.limited_by === 'cap'}<span class="cap"> · limited by the size cap</span>{/if}
        </p>
      {/if}
    {/if}
  </div>
  <div class="card">
    <h2 class="card-title">Dropped</h2>
    <div class="big" class:text-bad-fg={!!stats?.dropped_24h}>
      {stats ? num(stats.dropped_24h) : '—'} <small>last 24 h</small>
    </div>
    {#if stats}
      <p class="sub">
        {#if stats.dropped_by_reason?.queue_full}
          <a class="block text-link underline" href="#/about" title="Writing to disk fell behind and the UDP receive queue overflowed"
            >{num(stats.dropped_by_reason.queue_full)} because the UDP queue was full</a
          >
        {/if}
        {#if stats.kernel_dropped_24h === null}
          Kernel drops aren't visible on {osName}. <a class="text-link underline" href="#/about">Why</a>
        {:else}
          Kernel: {num(stats.kernel_dropped_24h)} dropped
        {/if}
        {#if stats.truncated_24h || stats.rejected_24h > 0}
          <span class="block">
            {#if stats.truncated_24h}<span class="whitespace-nowrap">{num(stats.truncated_24h)} truncated</span>{/if}
            {#if stats.truncated_24h && stats.rejected_24h > 0}·{/if}
            {#if stats.rejected_24h > 0}<a class="whitespace-nowrap text-link underline" href="#/settings" title="Senders outside the allowlist">{num(stats.rejected_24h)} rejected</a>{/if}
          </span>
        {/if}
      </p>
    {/if}
  </div>
</div>

<div class="mb-3 flex flex-wrap items-center gap-2" role="tablist" aria-label="Device groups">
  <button role="tab" class="tab" aria-selected={tab === ALL} onclick={() => setTab(ALL)}>All devices</button>
  {#each groups as g (g)}
    <button role="tab" class="tab" aria-selected={tab === g} onclick={() => setTab(g)}>{g}</button>
  {/each}
  {#if hasUngrouped && groups.length}
    <button role="tab" class="tab" aria-selected={tab === UNGROUPED} onclick={() => setTab(UNGROUPED)}>Ungrouped</button>
  {/if}
  <a class="tab" href="#/devices" title="Set groups on the Devices page" aria-label="Add a group on the Devices page"><Icon name="plus" size={16} /></a>
  {#if blockedCount}
    <label class="ml-auto flex items-center gap-2 text-[14px]">
      <input type="checkbox" bind:checked={showBlocked} /> Show blocked ({num(blockedCount)})
    </label>
  {/if}
</div>

<div class="strip mb-4" role="group" aria-label="Devices: click to show one in the live tail, Cmd or Ctrl-click for several">
  {#if strip && !strip.length}
    <p class="m-0 px-1 text-sm text-muted">
      {live.deviceTotal ? 'No devices match.' : 'No devices yet. Point a device at this machine on port 514.'}
      {#if !live.deviceTotal}<a class="text-link underline" href="#/welcome">Setup help</a>{/if}
    </p>
  {/if}
  {#each chips as d (d.id)}
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <span class="chipwrap" oncontextmenu={(e) => { e.preventDefault(); openMenu(d.id, e.clientX, e.clientY); }}>
      <button
        class="chip"
        class:isblocked={d.blocked}
        aria-pressed={picked.includes(d.id)}
        onclick={(e) => pick(d.id, e)}
        title="{label(d)}{d.name ? ` (${d.ip})` : ''} · {d.status} · last heard {ago(d.last_heard, live.now, NOW_WITHIN_S)} · {rate(d.msgs_per_min)}"
      >
        <StatusDot status={d.status} />
        <span class="nm">{label(d)}</span>
        {#if d.blocked}<span class="badge">blocked</span>{:else}<span class="meta">{d.status === 'online' ? rate(d.msgs_per_min) : agoShort(d.last_heard, live.now, NOW_WITHIN_S)}</span>{/if}
      </button>
      <button class="dots" aria-label="More for {label(d)}" title="Block or unblock" onclick={(e) => { const r = e.currentTarget.getBoundingClientRect(); openMenu(d.id, r.left, r.bottom + 4); }}>⋯</button>
    </span>
  {/each}
  {#if stripTotal > STRIP_MAX}
    <a class="chip more" href="#/devices">All {num(stripTotal)} devices →</a>
  {/if}
</div>

<div bind:this={tailBox}>
  <LiveTail
    group={tailGroup}
    ungrouped={tailUngrouped}
    devices={tailDevices}
    q={ui.filter}
    {scope}
    height="{tailHeight}px"
    onClearScope={picked.length || tab !== ALL ? () => setTab(ALL) : undefined}
    {eventsHref}
  />
</div>

<style>
  .big {
    font-size: 34px;
    font-weight: 700;
    letter-spacing: -1px;
    line-height: 1.2;
  }
  .est .cap {
    color: var(--warn-fg);
    font-weight: 600;
  }
  .sub {
    margin: 8px 0 0;
    font-size: 12.5px;
    line-height: 1.4;
    color: var(--muted);
  }
  .big small {
    font-size: 14px;
    color: var(--muted);
    font-weight: 500;
    letter-spacing: 0;
  }
  .strip {
    display: flex;
    gap: 8px;
    overflow-x: auto;
    padding: 2px 2px 6px;
    scrollbar-width: thin;
  }
  .chipwrap {
    position: relative;
    flex: none;
    display: inline-flex;
  }
  .chipwrap .chip {
    padding-right: 34px;
  }
  .dots {
    position: absolute;
    right: 6px;
    top: 50%;
    transform: translateY(-50%);
    width: 24px;
    height: 24px;
    border-radius: 50%;
    border: 0;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
    line-height: 1;
  }
  .dots:hover,
  .dots:focus-visible {
    background: var(--glass-strong);
    color: var(--fg);
  }
  .chip.isblocked .nm {
    color: var(--muted);
  }
  .badge {
    font-size: 11.5px;
    font-weight: 600;
    padding: 1px 7px;
    border-radius: 999px;
    border: 1px solid var(--input-border);
    color: var(--muted);
  }
  .chip {
    flex: none;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 7px 12px;
    border-radius: 999px;
    background: var(--glass);
    border: 1px solid var(--border);
    color: var(--fg);
    font: inherit;
    font-size: 13.5px;
    cursor: pointer;
    white-space: nowrap;
    text-decoration: none;
  }
  .chip:hover {
    background: var(--glass-strong);
  }
  .chip[aria-pressed='true'] {
    background: var(--chip);
    box-shadow: var(--shadow-chip), 0 0 0 2px var(--spark);
  }
  .chip .nm {
    font-weight: 600;
    max-width: 28ch;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .chip .meta {
    color: var(--muted);
    font-size: 12.5px;
    font-variant-numeric: tabular-nums;
  }
  .chip.more {
    color: var(--link);
    font-weight: 600;
  }
  .tab {
    display: inline-flex;
    align-items: center;
    padding: 9px 18px;
    border-radius: 999px;
    color: var(--fg);
    font-size: 15px;
    background: transparent;
    border: 0;
    cursor: pointer;
    text-decoration: none;
  }
  .tab:hover {
    background: var(--glass);
  }
  .tab[aria-selected='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
</style>

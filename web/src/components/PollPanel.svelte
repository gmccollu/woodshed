<script lang="ts">
  // The device page's Polling panel (SPEC §12.5): the system box, 5 small charts with 13 lines by
  // default (CPU, memory, total in/out, the 4 busiest interfaces in and out, errors plus discards),
  // restart and oper-change markers on every chart (every interface's, charted or not, from the
  // panel's own markers), the list of those changes, and the interface table. Clicking a row, or
  // "Chart" in the changes list, adds that interface to the interface chart (at most 8 at once).
  import { getPollDevice, getPollSeries, getPollTargets } from '../lib/api';
  import { ago, dateTime } from '../lib/format';
  import {
    aligned,
    bps,
    bucketsOf,
    CHART_COLORS,
    chartSet,
    count,
    delta,
    HEADLINE_KEYS,
    ifKey,
    ifSeriesBatches,
    markerTitle,
    MAX_CHARTED,
    pct,
    speed,
    statusLabel,
    sumAligned,
    toggleCharted,
    uptime,
    type ChartLine,
    type PollDevicePanel,
    type PollInterfaceRow,
    type PollMarker,
    type PollSeriesResponse,
    type PollTarget,
  } from '../lib/poll';
  import PollChart from './PollChart.svelte';

  let {
    device,
    from,
    to,
    utc = false,
    onedit,
  }: { device: string; from: string; to: string; utc?: boolean; onedit?: (t: PollTarget) => void } = $props();

  let panel = $state<PollDevicePanel | null>(null);
  let target = $state<PollTarget | null>(null);
  let head = $state<PollSeriesResponse | null>(null);
  let ifSeries = $state<PollSeriesResponse[]>([]);
  let loadError = $state('');
  let full = $state(false);
  /** Interfaces added to, or taken off, the server's default chart set. */
  let picked = $state<string[]>([]);
  let removed = $state<string[]>([]);
  let reload = $state(0);

  $effect(() => {
    const ctrl = new AbortController();
    const [id, f, t] = [device, from, to];
    void reload;
    (async () => {
      try {
        const [p, ts, h] = await Promise.all([
          getPollDevice(id, f, t, ctrl.signal),
          getPollTargets(),
          getPollSeries({ device: id, from: f, to: t, series: [...HEADLINE_KEYS] }, ctrl.signal),
        ]);
        panel = p;
        target = ts.find((x) => x.id === p.target_id) ?? ts.find((x) => x.device_id === id) ?? null;
        head = h;
        loadError = '';
      } catch (e) {
        if ((e as Error).name !== 'AbortError') loadError = (e as Error).message;
      }
    })();
    return () => ctrl.abort();
  });
  // Every minute: a new cycle has likely been stored.
  $effect(() => {
    const t = setInterval(() => reload++, 60_000);
    return () => clearInterval(t);
  });

  const charted = $derived(panel ? chartSet(panel.charted, picked, removed) : []);
  $effect(() => {
    if (!head) return;
    const names = charted;
    const ctrl = new AbortController();
    const [id, f, t, b] = [device, from, to, head.bucket_seconds];
    if (!names.length) {
      ifSeries = [];
      return;
    }
    Promise.all(ifSeriesBatches(names).map((keys) => getPollSeries({ device: id, from: f, to: t, bucket: b, series: keys }, ctrl.signal))).then(
      (r) => (ifSeries = r),
      (e) => {
        if ((e as Error).name !== 'AbortError') loadError = (e as Error).message;
      },
    );
    return () => ctrl.abort();
  });

  const grid = $derived(head ? bucketsOf(from, to, head.bucket_seconds, head.series.map((s) => s.points)) : null);
  const vals = (r: PollSeriesResponse | null | undefined, key: string, total = false) => {
    const s = r?.series.find((x) => x.key === key);
    return grid && s ? aligned(s.points, grid.start, grid.size, grid.n, total) : [];
  };
  // The panel's markers hold every interface's changes, charted or not (a down on an interface no
  // one is looking at is often the evidence); the series' markers add the charted ones'.
  const markers = $derived.by(() => {
    const all: PollMarker[] = [...(panel?.markers ?? []), ...(head?.markers ?? []), ...ifSeries.flatMap((r) => r.markers)];
    const seen = new Set<string>();
    return all
      .filter((m) => {
        const k = `${m.time}|${m.kind}|${m.if ?? ''}`;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
      })
      .sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  });
  // The changes list: newest first, the first CHANGES_SHOWN unless the user asks for all.
  const CHANGES_SHOWN = 8;
  let allChanges = $state(false);
  const changes = $derived([...markers].reverse());
  const changeTime = (iso: string) => (utc ? `${iso.slice(0, 16).replace('T', ' ')} UTC` : dateTime(iso));
  const ifVals = (name: string, what: 'in_bps' | 'out_bps') => {
    for (const r of ifSeries) {
      const v = vals(r, ifKey(name, what));
      if (v.length) return v;
    }
    return [];
  };
  const colorOf = (name: string) => CHART_COLORS[charted.indexOf(name) % CHART_COLORS.length];
  const ifLines = $derived<ChartLine[]>(
    charted.flatMap((n) => [
      { label: `${n} in`, color: colorOf(n), values: ifVals(n, 'in_bps') },
      { label: `${n} out`, color: colorOf(n), dash: true, values: ifVals(n, 'out_bps') },
    ]),
  );
  const noHr = $derived(!!target && !target.state.host_resources && target.state.status !== 'pending');

  // ----- the interface table -----
  type SortKey = 'name' | 'oper' | 'speed' | 'in' | 'out' | 'peak' | 'err' | 'disc';
  let sortBy = $state<SortKey>('peak');
  let desc = $state(true);
  const COLS: { k: SortKey; label: string; num?: boolean }[] = [
    { k: 'name', label: 'Interface' },
    { k: 'oper', label: 'Status' },
    { k: 'speed', label: 'Speed', num: true },
    { k: 'in', label: 'In now', num: true },
    { k: 'out', label: 'Out now', num: true },
    { k: 'peak', label: 'Peak in / out', num: true },
    { k: 'err', label: 'Errors', num: true },
    { k: 'disc', label: 'Discards', num: true },
  ];
  const sum = (a: number | null, b: number | null) => (a === null && b === null ? -1 : (a ?? 0) + (b ?? 0));
  function sortVal(r: PollInterfaceRow, k: SortKey): number | string {
    switch (k) {
      case 'name':
        return r.index;
      case 'oper':
        return r.oper;
      case 'speed':
        return r.speed_mbps ?? -1;
      case 'in':
        return r.in_bps ?? -1;
      case 'out':
        return r.out_bps ?? -1;
      case 'peak':
        return sum(r.peak_in_bps, r.peak_out_bps);
      case 'err':
        return sum(r.in_err_d, r.out_err_d);
      case 'disc':
        return sum(r.in_disc_d, r.out_disc_d);
    }
  }
  const rows = $derived.by(() => {
    const list = [...(panel?.interfaces ?? [])];
    list.sort((a, b) => {
      const x = sortVal(a, sortBy);
      const y = sortVal(b, sortBy);
      const c = typeof x === 'string' ? x.localeCompare(y as string) : (x as number) - (y as number);
      return (desc ? -c : c) || a.index - b.index;
    });
    return list;
  });
  function sortOn(k: SortKey) {
    if (sortBy === k) desc = !desc;
    else {
      sortBy = k;
      desc = k !== 'name' && k !== 'oper';
    }
  }
  function toggle(name: string) {
    if (!panel) return;
    const r = toggleCharted(charted, name, panel.charted, picked, removed);
    full = r.full;
    if (!r.full) {
      picked = r.picked;
      removed = r.removed;
    }
  }
  const operTone = (o: string) => (o === 'up' ? 'ok' : o === 'down' || o === 'lowerLayerDown' ? 'bad' : 'none');
  const lastRestartText = $derived.by(() => {
    const r = panel?.system.last_restart;
    if (!r) return '';
    const m = markers.find((x) => x.kind === 'restart' && x.time === r);
    const what = m?.reboot === '1' ? 'rebooted' : m?.reboot === '0' ? 'agent restarted' : 'restarted';
    return `${what} ${ago(r)}`;
  });
</script>

<section class="card" aria-labelledby="poll-h">
  <div class="flex flex-wrap items-baseline justify-between gap-2">
    <h2 class="m-0 text-[17px] font-bold" id="poll-h">Polling</h2>
    {#if target && onedit}<button class="ghost-btn" onclick={() => onedit?.(target!)}>Edit polling</button>{/if}
  </div>
  {#if loadError}
    <p class="text-bad-fg" role="alert">Couldn't load the poll data: {loadError}</p>
  {:else if !panel || !head}
    <p class="text-muted">Loading…</p>
  {:else}
    <dl class="sys">
      <div>
        <dt>Uptime</dt>
        <dd>
          {uptime(panel.system.uptime_s)}
          {#if lastRestartText}<span class="sub" title={dateTime(panel.system.last_restart!)}>{lastRestartText}</span>{/if}
        </dd>
      </div>
      <div><dt>sysName</dt><dd>{panel.system.sys_name || '–'}</dd></div>
      <div><dt>Polled at</dt><dd class="font-mono text-[13px]">{panel.address}{target && target.port !== 161 ? `:${target.port}` : ''}</dd></div>
      {#if target}
        <div>
          <dt>Last cycle</dt>
          <dd>
            {#if target.state.last_attempt}<span title={dateTime(target.state.last_attempt)}>{ago(target.state.last_attempt)}</span>{:else}–{/if}
            {#if target.state.rtt_ms !== null}<span class="sub">round trip {target.state.rtt_ms} ms</span>{/if}
          </dd>
        </div>
        <div>
          <dt>Status</dt>
          <dd><span class="chip {target.state.status}">{statusLabel(target.state.status)}</span>
            <span class="sub">v{target.version}, every {target.interval_s >= 60 ? `${target.interval_s / 60} min` : `${target.interval_s} s`}</span></dd>
        </div>
      {/if}
      {#if panel.system.cpu}<div><dt>CPU</dt><dd>{pct(panel.system.cpu.now)} <span class="sub">peak {pct(panel.system.cpu.peak)}</span></dd></div>{/if}
      {#if panel.system.mem_used_pct}<div><dt>Memory</dt><dd>{pct(panel.system.mem_used_pct.now)} <span class="sub">peak {pct(panel.system.mem_used_pct.peak)}</span></dd></div>{/if}
      {#if panel.system.sys_descr}<div class="wide"><dt>sysDescr</dt><dd>{panel.system.sys_descr}</dd></div>{/if}
    </dl>
    {#if target?.state.error && target.state.status !== 'ok'}<p class="warnline" role="status">Last failure: {target.state.error}</p>{/if}
    {#if target && !target.state.hc_counters && target.state.status !== 'pending'}
      <p class="warnline">32-bit counters: rates above about 115 Mb/s at a 5-minute interval can be wrong.</p>
    {/if}

    <div class="charts">
      <PollChart title="CPU" unit="%" fixedTop={100} {from} {to} {utc} start={grid!.start} size={grid!.size} {markers}
        note={noHr ? 'CPU and memory: not available on this device.' : ''}
        lines={[{ label: 'CPU', color: 'var(--chart-1)', values: vals(head, 'cpu') }]} />
      <PollChart title="Memory used" unit="%" fixedTop={100} {from} {to} {utc} start={grid!.start} size={grid!.size} {markers}
        note={noHr ? 'CPU and memory: not available on this device.' : ''}
        caption="As the agent reports it: on Linux with net-snmp, used includes the page cache, so an idle host can show about 90 %."
        lines={[{ label: 'Memory', color: 'var(--chart-5)', values: vals(head, 'mem_used_pct') }]} />
      <PollChart title="Traffic, all interfaces" unit="bit/s" {from} {to} {utc} start={grid!.start} size={grid!.size} {markers}
        lines={[
          { label: 'In', color: 'var(--chart-1)', values: vals(head, 'in_bps') },
          { label: 'Out', color: 'var(--chart-2)', dash: true, values: vals(head, 'out_bps') },
        ]} />
      <PollChart title="Errors and discards, all interfaces" unit="count" {from} {to} {utc} start={grid!.start} size={grid!.size} {markers}
        lines={[{ label: 'Errors + discards per bucket', color: 'var(--chart-8)', values: sumAligned(vals(head, 'errors_d', true), vals(head, 'discards_d', true)) }]} />
      <div class="wide">
        <PollChart title={charted.length ? `Interfaces: ${charted.join(', ')}` : 'Interfaces'} unit="bit/s" {from} {to} {utc} start={grid!.start} size={grid!.size} {markers}
          note={charted.length ? '' : 'No interface had traffic in this range. Click an interface below to chart it.'}
          lines={ifLines} />
      </div>
    </div>

    <div class="mt-4">
      <h3 class="m-0 text-[14px] font-semibold" id="poll-changes-h">Restarts and interface changes ({changes.length}{changes.length >= 100 ? '+' : ''})</h3>
      {#if changes.length}
        <ul class="changes" aria-labelledby="poll-changes-h">
          {#each allChanges ? changes : changes.slice(0, CHANGES_SHOWN) as m (`${m.time}|${m.kind}|${m.if ?? ''}`)}
            {@const uncharted = m.kind === 'oper' && !!m.if && !charted.includes(m.if)}
            <li>
              <time datetime={m.time}>{changeTime(m.time)}</time>
              <span class="chip {m.kind === 'restart' ? 'restart' : operTone(m.oper ?? '')}">{m.kind === 'restart' ? (m.reboot === '1' ? 'reboot' : 'restart') : (m.oper ?? 'change')}</span>
              <span class="what">{markerTitle(m)}</span>
              {#if uncharted}
                <span class="sub">not charted</span>
                <button class="linkbtn" onclick={() => toggle(m.if!)}>Chart {m.if}</button>
              {/if}
            </li>
          {/each}
        </ul>
        {#if changes.length > CHANGES_SHOWN}
          <button class="linkbtn mt-1" aria-expanded={allChanges} onclick={() => (allChanges = !allChanges)}>
            {allChanges ? `Show the newest ${CHANGES_SHOWN}` : `Show all ${changes.length}`}
          </button>
        {/if}
      {:else}
        <p class="m-0 mt-1 text-[13px] text-muted">None in this range.</p>
      {/if}
    </div>

    <div class="mt-4 flex flex-wrap items-baseline justify-between gap-2">
      <h3 class="m-0 text-[14px] font-semibold">Interfaces ({panel.interfaces.length})</h3>
      <span class="text-[12.5px] text-muted" aria-live="polite">
        {#if full}At most {MAX_CHARTED} interfaces are charted at once; take one off first.{:else}Click a row to add it to the chart or take it off ({charted.length} of {MAX_CHARTED}).{/if}
      </span>
    </div>
    {#if panel.interfaces_left_out}
      <p class="warnline">
        {panel.interfaces_left_out} interface{panel.interfaces_left_out === 1 ? ' isn’t' : 's aren’t'} polled: the cap is {target?.max_interfaces ?? 64} per device.
        Pinned interfaces are polled first, then those that are up, fastest first.
        {#if target && onedit}<button class="linkbtn" onclick={() => onedit?.(target!)}>Pin interfaces or raise the cap</button>{/if}
      </p>
    {/if}
    <div class="overflow-x-auto">
      <table class="ift">
        <thead>
          <tr>
            <th scope="col"><span class="sr-only">Charted</span></th>
            {#each COLS as c (c.k)}
              <th scope="col" class:text-right={c.num} aria-sort={sortBy === c.k ? (desc ? 'descending' : 'ascending') : undefined}>
                <button class="sort" class:on={sortBy === c.k} onclick={() => sortOn(c.k)}>{c.label}{#if sortBy === c.k}<span aria-hidden="true">{desc ? ' ↓' : ' ↑'}</span>{/if}</button>
              </th>
            {/each}
          </tr>
        </thead>
        <tbody>
          {#each rows as r (r.index)}
            {@const on = charted.includes(r.name)}
            <tr class:on onclick={() => toggle(r.name)}>
              <td>
                <button class="pick" aria-pressed={on} aria-label="{on ? 'Take' : 'Chart'} {r.name}{on ? ' off the chart' : ''}" onclick={(e) => (e.stopPropagation(), toggle(r.name))}>
                  {#if on}<span class="sw" style:border-color={colorOf(r.name)}></span>{:else}<span class="plus">+</span>{/if}
                </button>
              </td>
              <td><b class="font-mono text-[13px]">{r.name}</b>{#if r.alias}<span class="sub">{r.alias}</span>{/if}</td>
              <td><span class="chip {operTone(r.oper)}">{r.oper}</span>{#if r.oper_changes}<span class="sub">{r.oper_changes} change{r.oper_changes === 1 ? '' : 's'}</span>{/if}</td>
              <td class="text-right">{speed(r.speed_mbps)}</td>
              <td class="text-right">{bps(r.in_bps)}</td>
              <td class="text-right">{bps(r.out_bps)}</td>
              <td class="text-right">{bps(r.peak_in_bps)} / {bps(r.peak_out_bps)}</td>
              <td class="text-right" title="in / out">{delta(r.in_err_d)} / {delta(r.out_err_d)}</td>
              <td class="text-right" title="in / out">{delta(r.in_disc_d)} / {delta(r.out_disc_d)}</td>
            </tr>
          {:else}
            <tr><td colspan="9" class="text-muted">No interfaces polled{target?.presets.includes('interfaces') ? ' yet' : ' (the interfaces preset is off)'}.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if head.partial}<p class="text-[12.5px] text-muted">Some of the range wasn't read in time; the charts show what was.</p>{/if}
    <p class="text-[12px] text-muted">{count(panel.interfaces.length)} polled interface{panel.interfaces.length === 1 ? '' : 's'}; read from {head.source === 'rollup' ? 'the hourly rollups' : 'the poll files'}. Gaps are cycles that weren't measured.</p>
  {/if}
</section>

<style>
  .sys {
    display: flex;
    flex-wrap: wrap;
    gap: 10px 28px;
    margin: 12px 0 4px;
    font-size: 14px;
  }
  .sys dt {
    font-size: 12px;
    color: var(--muted);
  }
  .sys dd {
    margin: 0;
  }
  .sys .wide {
    flex-basis: 100%;
  }
  .sub {
    display: block;
    font-size: 12px;
    color: var(--muted);
  }
  .warnline {
    margin: 8px 0 0;
    padding: 6px 12px;
    border-radius: 12px;
    background: var(--warn-bg);
    border: 1px solid var(--warn-border);
    font-size: 13px;
  }
  .charts {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 22px 26px;
    margin-top: 16px;
  }
  .charts .wide {
    grid-column: 1 / -1;
  }
  @media (max-width: 760px) {
    .charts {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  .chip {
    display: inline-block;
    padding: 0 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--input-border);
    background: var(--chip);
  }
  .chip.ok {
    border-color: var(--ok);
    color: var(--ok-fg);
  }
  .chip.bad,
  .chip.backing_off {
    border-color: var(--bad);
    color: var(--bad-fg);
  }
  .chip.failing,
  .chip.restart {
    border-color: var(--warn);
    color: var(--warn-fg);
  }
  .changes {
    list-style: none;
    margin: 8px 0 0;
    padding: 0;
    font-size: 13.5px;
  }
  .changes li {
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 4px 10px;
    padding: 5px 0;
    border-bottom: 1px solid var(--divider);
  }
  .changes time {
    min-width: 11em;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
  }
  .changes .sub {
    display: inline;
  }
  .ift {
    width: 100%;
    margin-top: 8px;
    border-collapse: collapse;
    font-size: 13.5px;
    font-variant-numeric: tabular-nums;
  }
  .ift th {
    text-align: left;
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    padding: 6px 8px;
    border-bottom: 1px solid var(--divider);
    white-space: nowrap;
  }
  .ift th.text-right {
    text-align: right;
  }
  .ift td {
    padding: 6px 8px;
    border-bottom: 1px solid var(--divider);
    white-space: nowrap;
    cursor: pointer;
  }
  .ift tr:hover td,
  .ift tr.on td {
    background: var(--glass-strong);
  }
  .sort {
    background: none;
    border: 0;
    padding: 0;
    font: inherit;
    color: inherit;
    cursor: pointer;
  }
  .sort.on {
    color: var(--fg);
  }
  .pick {
    width: 24px;
    height: 20px;
    padding: 0;
    border-radius: 6px;
    border: 1px solid var(--input-border);
    background: var(--input);
    cursor: pointer;
    color: var(--muted);
    line-height: 1;
  }
  .pick .sw {
    display: inline-block;
    width: 14px;
    border-top: 3px solid;
    vertical-align: middle;
  }
  .linkbtn {
    background: none;
    border: 0;
    padding: 0;
    font: inherit;
    color: var(--link);
    text-decoration: underline;
    cursor: pointer;
  }
</style>

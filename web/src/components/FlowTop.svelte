<script lang="ts">
  // The Flows tab's Top panel (SPEC §13.3): top talkers, destination ports, conversations and the
  // Denied view (top denied sources, destinations, ports and rules), or any key and metric, over
  // the search's window, devices and filters (GET /api/flows/top). A partial answer keeps going
  // with its cursor, like the field panel, for up to a minute; each answer carries running totals.
  // Clicking a row adds it to the search's filters.
  import { ApiError, getFlowTop } from '../lib/api';
  import {
    addFilters,
    amountText,
    defaultMetric,
    METRICS,
    progressText,
    rowScaled,
    rowValue,
    shareText,
    short,
    TOP_BYS,
    TOP_VIEWS,
    type FlowBy,
    type FlowMetric,
    type FlowTopResponse,
    rowFilters,
  } from '../lib/flows';
  import { stamp } from '../lib/format';

  let {
    from,
    to,
    scope,
    excludeDevices = [],
    filters,
    utc = false,
    view = $bindable('talkers'),
    onpick,
  }: {
    from: string;
    to: string;
    scope: { devices?: string[]; group?: string; ungrouped?: boolean };
    excludeDevices?: string[];
    filters: Record<string, string[]>;
    utc?: boolean;
    view?: string;
    /** Filters to add to the search (a row's key). */
    onpick: (add: Record<string, string[]>) => void;
  } = $props();

  const COUNT_FOR_MS = 60_000;
  let customBy = $state<FlowBy>('dst');
  let customMetric = $state<FlowMetric | ''>('');

  const tables = $derived.by(() => {
    if (view === 'custom') return [{ by: customBy, label: `Top ${TOP_BYS.find((b) => b.by === customBy)?.label.toLowerCase()}`, metric: customMetric || undefined, filters: undefined }];
    return TOP_VIEWS.find((v) => v.key === view)?.tables ?? TOP_VIEWS[0].tables;
  });

  interface Table {
    res: FlowTopResponse | null;
    status: 'running' | 'paused' | 'done' | 'error';
    error: string;
  }
  let results = $state<Table[]>([]);
  let gen = 0;

  const key = $derived(JSON.stringify({ from, to, scope, excludeDevices, filters, tables }));
  $effect(() => {
    const k = JSON.parse(key) as { tables: typeof tables };
    const my = ++gen;
    const ctrl = new AbortController();
    results = k.tables.map(() => ({ res: null, status: 'running', error: '' }));
    k.tables.forEach((t, i) => count(i, t, my, ctrl.signal));
    return () => ctrl.abort();
  });

  async function count(i: number, t: (typeof tables)[number], my: number, signal: AbortSignal, cursor = '', spent = 0) {
    const f = addFilters(filters, t.filters ?? {});
    try {
      for (;;) {
        const res = await getFlowTop(
          { ...scope, exclude_devices: excludeDevices, from, to, by: t.by, metric: t.metric, filters: f, top: 10, cursor: cursor || undefined },
          signal,
        );
        if (my !== gen) return;
        spent += res.elapsed_ms;
        cursor = res.next_cursor;
        const more = res.partial && !!cursor;
        results[i] = { res, status: !more ? 'done' : spent >= COUNT_FOR_MS ? 'paused' : 'running', error: '' };
        if (!more || spent >= COUNT_FOR_MS) {
          resume[i] = more ? () => count(i, t, my, signal, cursor, 0) : null;
          return;
        }
      }
    } catch (x) {
      if (my !== gen || (x as Error).name === 'AbortError') return;
      results[i] = { res: null, status: 'error', error: x instanceof ApiError ? x.message : (x as Error).message };
    }
  }
  const resume: ((() => void) | null)[] = [];

  /** The metric a table counts (its own, else the default for its filters). */
  const metricOf = (t: (typeof tables)[number]) => t.metric ?? defaultMetric(addFilters(filters, t.filters ?? {}));
  const valueText = (m: FlowMetric, r: { bytes: number; packets: number; flows: number; connections?: number }, scaled: number | null, lower: boolean) =>
    m === 'bytes' || m === 'packets' ? amountText(m, m === 'bytes' ? r.bytes : r.packets, scaled, { lowerBound: lower }) : short(m === 'flows' ? r.flows : (r.connections ?? r.flows));
  const range = (a: string, b: string) => `${stamp(a, utc)} → ${stamp(b, utc)}${utc ? ' UTC' : ''}`;
  const unitOf = (m: FlowMetric) => (m === 'bytes' ? 'bytes' : m === 'packets' ? 'packets' : m === 'flows' ? 'flow records' : 'connections');

  function pick(t: (typeof tables)[number], k: string) {
    onpick(addFilters(rowFilters(t.by, k), t.filters ?? {}));
  }
</script>

<section class="top" aria-label="Top" data-flow-top>
  <div class="tbar">
    <b class="text-white">Top</b>
    <div class="seg" role="tablist" aria-label="Top view">
      {#each TOP_VIEWS as v (v.key)}
        <button type="button" role="tab" aria-selected={view === v.key} onclick={() => (view = v.key)}>{v.label}</button>
      {/each}
      <button type="button" role="tab" aria-selected={view === 'custom'} onclick={() => (view = 'custom')}>By…</button>
    </div>
    {#if view === 'custom'}
      <label class="pick">By <select bind:value={customBy}>{#each TOP_BYS as b (b.by)}<option value={b.by}>{b.label}</option>{/each}</select></label>
      <label class="pick"
        >Metric <select bind:value={customMetric}
          ><option value="">Default</option>{#each METRICS as m (m.metric)}<option value={m.metric}>{m.label}</option>{/each}</select
        ></label
      >
    {/if}
  </div>
  {#if view === 'denied'}
    <p class="note">Denied firewall events (fw_event=denied), counted by event: a denied connection carries no bytes.</p>
  {/if}
  <div class="tables" class:grid4={tables.length > 1}>
    {#each tables as t, i (t.by + t.label + i)}
      {@const r = results[i]}
      {@const m = metricOf(t)}
      <div class="tbl" data-top-by={t.by}>
        <h4>
          {t.label}
          <span class="by">by {unitOf(m)}</span>
          {#if r?.res?.approx}<span class="approx" title="More than 1,000,000 distinct keys: the counts past them are a space-saving estimate">approximate</span>{/if}
        </h4>
        {#if r?.status === 'error'}
          <p class="err" role="alert">{r.error}</p>
        {:else if !r?.res}
          <p class="dim">Counting…</p>
        {:else if !r.res.rows.length}
          <p class="dim">{t.filters?.fw_event ? 'No denied events in this window.' : 'Nothing in this window.'}</p>
        {:else}
          <ol>
            {#each r.res.rows as row (row.key)}
              <li title="{row.label}: {range(row.first, row.last)}">
                <span class="meter" style:width="{Math.max(1.5, row.share * 100)}%" aria-hidden="true"></span>
                <button type="button" class="k" onclick={() => pick(t, row.key)} title="Add {row.label} to the filters">{row.label}{row.label !== row.key && t.by !== 'conversation' ? ` (${row.key})` : ''}</button>
                <span class="v">{valueText(m, { ...row, connections: rowValue(row, 'connections') }, rowScaled(row, m), row.scaled_lower_bound)}</span>
                <span class="s">{shareText(row.share)}</span>
              </li>
            {/each}
          </ol>
          <div class="tot">
            Total {valueText(m, r.res.total, m === 'bytes' ? r.res.total.bytes_scaled : m === 'packets' ? r.res.total.packets_scaled : null, !r.res.total.scaled_complete)}
            {#if r.res.other.flows}· others {short(r.res.other.flows)} flow records{/if}
          </div>
        {/if}
        {#if r?.res && r.status !== 'done'}
          <p class="prog" aria-live="polite">
            {progressText(r.res.progress, true)}{r.status === 'running' ? '…' : '.'}
            {#if r.status === 'paused' && resume[i]}<button type="button" class="tail-btn" onclick={() => resume[i]?.()}>Count the rest</button>{/if}
          </p>
        {/if}
      </div>
    {/each}
  </div>
</section>

<style>
  .top {
    padding: 8px 18px 10px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    font-family: var(--font-sans);
    font-size: 13px;
    color: var(--log-fg);
  }
  .tbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 12px;
  }
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 999px;
    padding: 2px;
  }
  .seg button {
    border: 0;
    background: transparent;
    color: var(--log-fg);
    padding: 3px 11px;
    border-radius: 999px;
    font-size: 12.5px;
    cursor: pointer;
  }
  .seg button[aria-selected='true'] {
    background: rgba(255, 255, 255, 0.16);
    font-weight: 600;
  }
  .pick {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--log-dim);
  }
  .pick select {
    background: var(--log-bar);
    color: var(--log-fg);
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 8px;
    padding: 2px 6px;
    font-size: 12.5px;
  }
  .note {
    margin: 6px 0 0;
    color: var(--log-dim);
    font-size: 12.5px;
  }
  .tables {
    display: grid;
    gap: 10px 22px;
    margin-top: 8px;
  }
  @media (min-width: 900px) {
    .tables.grid4 {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }
  h4 {
    margin: 0 0 4px;
    font-size: 13px;
    font-weight: 700;
    color: #fff;
    display: flex;
    flex-wrap: wrap;
    gap: 2px 8px;
    align-items: baseline;
  }
  .by {
    font-weight: 400;
    font-size: 12px;
    color: var(--log-dim);
  }
  .approx {
    font-weight: 600;
    font-size: 11.5px;
    color: var(--sev-warn);
  }
  ol {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  li {
    position: relative;
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 2px 6px;
    border-radius: 6px;
  }
  .meter {
    position: absolute;
    left: 0;
    top: 1px;
    bottom: 1px;
    border-radius: 6px;
    background: rgba(120, 170, 255, 0.16);
  }
  .k {
    position: relative;
    min-width: 0;
    flex: 1 1 auto;
    text-align: left;
    border: 0;
    background: transparent;
    color: var(--log-fg);
    font-family: var(--font-mono);
    font-size: 12.5px;
    cursor: pointer;
    padding: 1px 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .k:hover {
    text-decoration: underline;
  }
  .v {
    position: relative;
    flex: none;
    font-family: var(--font-mono);
    font-size: 12.5px;
    font-variant-numeric: tabular-nums;
    text-align: right;
  }
  .s {
    position: relative;
    flex: none;
    width: 3.6em;
    text-align: right;
    color: var(--log-dim);
    font-variant-numeric: tabular-nums;
  }
  .tot,
  .dim,
  .prog {
    margin: 4px 0 0;
    color: var(--log-dim);
    font-size: 12.5px;
  }
  .prog {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    color: var(--sev-warn);
  }
  .err {
    margin: 0;
    color: var(--sev-err);
  }
  .tail-btn {
    padding: 2px 9px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.18);
    background: transparent;
    color: var(--log-fg);
    cursor: pointer;
    font-size: 12.5px;
  }
</style>

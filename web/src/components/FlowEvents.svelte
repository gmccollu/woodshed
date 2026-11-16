<script lang="ts">
  // The Events Flows tab (type=flow, SPEC §13.3): flow records over flow time (a record matches a
  // window its start-to-end overlaps), filtered by addresses, ports, protocol, interfaces, firewall
  // and NAT events and rule IDs; the field panel (flows per value, bytes beside them), the
  // histogram (flows or bytes per bucket), the Top panel and the results, newest first by flow end.
  // Flows have no text, so there's no q box. Partial answers report how much of the window they
  // counted (progress), not a counted-from time, and keep going like the field panel.
  //
  // The page URL holds type=flow, the devices, the range, the order, each filter by its parameter
  // name, top=<view> and hm=<histogram metric>. In the bundle preview the window and devices are
  // the bundle's (props) and the URL is left to Events.
  import { untrack } from 'svelte';
  import {
    ApiError,
    getSavedSearch,
    getSummary,
    searchFlows,
    SUMMARY_EXPIRED,
    type DataType,
    type FieldDescriptor,
    type FieldValueCount,
    type SavedSearch,
    type SearchParams,
    type SummaryResponse,
  } from '../lib/api';
  import {
    amountText,
    dbytes,
    detailRows,
    endpoint,
    eventNote,
    extraText,
    filterErrors,
    FLOW,
    FLOW_FILTERS,
    FLOW_PARAMS,
    progressText,
    protoName,

    splitValues,
    type FlowResult,
  } from '../lib/flows';
  import { cleanFilters, excludeValue, filtersFromQuery, filtersOfSaved, filtersToQuery, includeValue, removeValue, typeToQuery, type TypeFilters } from '../lib/traps';
  import { addItem, domainChips, domainExclude, domainInclude, domainRemove, extrasFromQuery, extrasToQuery, formOfSaved, noExtras, removeItem, type Chip } from '../lib/events';
  import { num, stamp } from '../lib/format';
  import { prefs } from '../lib/prefs.svelte';
  import { defaultRange, rangeFromQuery, rangeToQuery, resolveRange, type Range } from '../lib/range';
  import { go, router, setQuery } from '../lib/router.svelte';
  import { allScope, scopeFromQuery, scopeLabel, scopeParams, scopeToQuery, type Scope } from '../lib/scope';
  import { deviceName } from '../lib/status.svelte';
  import DevicePicker from './DevicePicker.svelte';
  import FieldPanel from './FieldPanel.svelte';
  import FlowTop from './FlowTop.svelte';
  import Histogram from './Histogram.svelte';
  import Icon from './Icon.svelte';
  import SavedMenu from './SavedMenu.svelte';
  import TimeRange from './TimeRange.svelte';

  let {
    types,
    ontype,
    fixed = null,
    onbundle,
    onzoom,
  }: {
    /** The type switch's types (Events shows the same switch on every tab). */
    types: DataType[];
    ontype: (t: string) => void;
    /** The bundle preview's window and devices, or null. */
    fixed?: { from: string; to: string; scope: Scope } | null;
    /** "Bundle around this" from a record or the histogram. */
    onbundle?: (at: string) => void;
    /** A drag across the histogram in the bundle preview (it narrows the bundle). */
    onzoom?: (from: string, to: string) => void;
  } = $props();

  const PAGE = 500;
  const COUNT_FOR_MS = 60_000;
  const schema = $derived(types.find((t) => t.type === FLOW) ?? null);

  // ----- the form -----
  let scope = $state<Scope>(allScope());
  let range = $state<Range>(defaultRange());
  let order = $state<'desc' | 'asc'>('desc');
  let xdev = $state<string[]>([]);
  /** The filter boxes' text, by parameter name. */
  let boxes = $state<Record<string, string>>({});
  let filters = $state<TypeFilters>({});
  let more = $state(false);
  let view = $state('talkers');
  let showTop = $state(true);
  let hmetric = $state<'flows' | 'bytes'>('flows');
  let boxErrors = $state<Record<string, string>>({});
  let rangeError = $state('');
  let savedCur = $state<SavedSearch | null>(null);
  let savedEtag = $state('');

  function setFilters(f: TypeFilters) {
    filters = cleanFilters(f);
    const b: Record<string, string> = {};
    for (const p of FLOW_PARAMS) if (filters[p]?.length) b[p] = filters[p].join(', ');
    boxes = b;
  }

  function toQuery(): string {
    const p = new URLSearchParams();
    typeToQuery(FLOW, p);
    scopeToQuery(scope, p);
    rangeToQuery(range, p);
    extrasToQuery({ ...noExtras(), xdev }, p);
    filtersToQuery(filters, p);
    if (order === 'asc') p.set('order', 'asc');
    if (view !== 'talkers') p.set('top', view);
    if (hmetric !== 'flows') p.set('hm', hmetric);
    if (savedCur) p.set('saved', savedCur.id);
    return p.toString();
  }

  function fromQuery(s: string) {
    const p = new URLSearchParams(s);
    scope = scopeFromQuery(p);
    range = rangeFromQuery(p);
    order = p.get('order') === 'asc' ? 'asc' : 'desc';
    xdev = extrasFromQuery(p).xdev;
    setFilters(filtersFromQuery(p, FLOW_PARAMS));
    view = p.get('top') ?? 'talkers';
    hmetric = p.get('hm') === 'bytes' ? 'bytes' : 'flows';
    if (FLOW_PARAMS.some((k) => !FLOW_FILTERS.find((d) => d.main && (d.param === k || d.exclude === k)) && filters[k]?.length)) more = true;
    const id = p.get('saved') ?? '';
    if (!id) savedCur = null;
    else if (id !== savedCur?.id)
      getSavedSearch(id).then(
        (r) => ((savedCur = r.saved), (savedEtag = r.etag)),
        () => (savedCur = null),
      );
  }

  let lastRun = '';
  let opened = false;
  $effect(() => {
    if (fixed) {
      const k = JSON.stringify(fixed);
      if (k !== lastRun) {
        lastRun = k;
        const first = !opened;
        opened = true;
        untrack(() => {
          if (first) fromQuery(router.query);
          run();
        });
      }
      return;
    }
    const s = router.query;
    if (s !== lastRun || !opened) {
      opened = true;
      untrack(() => {
        fromQuery(s);
        run();
      });
    }
  });

  // ----- the search -----
  let active = $state<SearchParams | null>(null);
  let activeScope = $state<Scope>(allScope());
  let activeX = $state<string[]>([]);
  let activeF = $state<TypeFilters>({});
  let results = $state.raw<FlowResult[]>([]);
  let seen = new Set<string>();
  let cursor = $state('');
  let status = $state<'idle' | 'running' | 'done' | 'cancelled' | 'error'>('idle');
  let error = $state('');
  let ctrl: AbortController | null = null;
  let gen = 0;

  let summary = $state.raw<SummaryResponse | null>(null);
  let sumStatus = $state<'idle' | 'running' | 'paused' | 'done' | 'error'>('idle');
  let sumError = $state('');
  let sumCursor = '';
  let sumCtrl: AbortController | null = null;
  let sumGen = 0;

  function cancel() {
    ctrl?.abort();
    gen++;
    if (status === 'running') status = 'cancelled';
    sumCtrl?.abort();
    sumGen++;
    if (sumStatus === 'running') sumStatus = summary?.next_cursor ? 'paused' : 'idle';
  }

  /** The boxes as filters: every value checked first, so a typo is shown under its box. */
  function readBoxes(): TypeFilters | null {
    const f: TypeFilters = {};
    for (const [k, v] of Object.entries(boxes)) {
      const xs = splitValues(v);
      if (xs.length) f[k] = xs;
    }
    boxErrors = filterErrors(f);
    if (Object.keys(boxErrors).length) {
      more = more || Object.keys(boxErrors).some((k) => !FLOW_FILTERS.find((d) => d.main && d.param === k));
      return null;
    }
    return cleanFilters(f);
  }

  function submit(e: SubmitEvent) {
    e.preventDefault();
    const f = readBoxes();
    if (!f) return;
    filters = f;
    run();
  }

  async function run() {
    cancel();
    error = sumError = rangeError = '';
    const { from, to } = fixed ?? resolveRange(range);
    if (!from || !to || !(Date.parse(from) < Date.parse(to))) {
      rangeError = '"From" must be before "To".';
      status = 'error';
      return;
    }
    const sc = fixed?.scope ?? scope;
    if (!fixed) {
      lastRun = toQuery();
      setQuery(lastRun);
    }
    activeScope = $state.snapshot(sc) as Scope;
    activeX = [...xdev];
    activeF = cleanFilters($state.snapshot(filters) as TypeFilters);
    active = { q: '', type: FLOW, ...scopeParams(sc), from, to, order, limit: PAGE, exclude_devices: [...xdev], filters: activeF };
    results = [];
    seen = new Set();
    cursor = '';
    summary = null;
    sumCursor = '';
    countSummary();
    await fetchPage();
  }

  async function fetchPage() {
    if (!active) return;
    const my = ++gen;
    ctrl = new AbortController();
    status = 'running';
    let got = 0;
    try {
      for (;;) {
        const res = await searchFlows({ ...active, limit: PAGE - got, cursor: cursor || undefined }, ctrl.signal);
        if (my !== gen) return;
        const fresh = res.results.filter((r) => !seen.has(r.ref));
        for (const r of fresh) seen.add(r.ref);
        if (fresh.length) results = results.concat(fresh);
        got += fresh.length;
        cursor = res.next_cursor;
        if (!(res.partial && res.next_cursor) || got >= PAGE) break;
      }
      status = 'done';
    } catch (x) {
      if (my !== gen || (x as Error).name === 'AbortError') return;
      status = 'error';
      error = (x as Error).message;
    }
  }

  async function countSummary() {
    if (!active) return;
    sumCtrl?.abort();
    const my = ++sumGen;
    const c = new AbortController();
    sumCtrl = c;
    sumStatus = 'running';
    sumError = '';
    const { order: _o, limit: _l, cursor: _c, ...base } = active;
    let spent = 0;
    let restarted = false;
    try {
      for (;;) {
        let res: SummaryResponse;
        try {
          res = await getSummary({ ...base, metric: hmetric, cursor: sumCursor || undefined }, c.signal);
        } catch (x) {
          if (x instanceof ApiError && x.status === 400 && x.message === SUMMARY_EXPIRED && !restarted) {
            restarted = true;
            sumCursor = '';
            continue;
          }
          throw x;
        }
        if (my !== sumGen) return;
        summary = res;
        sumCursor = res.next_cursor;
        spent += res.elapsed_ms;
        if (!(res.partial && res.next_cursor)) {
          sumStatus = 'done';
          return;
        }
        if (spent >= COUNT_FOR_MS) {
          sumStatus = 'paused';
          return;
        }
      }
    } catch (x) {
      if (my !== sumGen || (x as Error).name === 'AbortError') return;
      sumStatus = 'error';
      sumError = (x as Error).message;
    }
  }

  function setMetric(m: 'flows' | 'bytes') {
    if (m === hmetric) return;
    hmetric = m;
    if (!fixed) setQuery((lastRun = toQuery()));
    sumCursor = '';
    countSummary();
  }

  $effect(() => {
    void view;
    if (!fixed && opened && active) {
      const q = toQuery();
      if (q !== lastRun) setQuery((lastRun = q));
    }
  });

  // ----- the field panel -----
  const domainOf = (f: FieldDescriptor) => (f.domain ?? []).map((d) => d.value);
  function pick(f: FieldDescriptor, value: string, exclude: boolean) {
    if (f.param === 'devices') {
      if (fixed) return;
      if (exclude) {
        xdev = addItem(xdev, value);
        if (scope.mode === 'devices' && scope.devices.length > 1) scope = { ...scope, devices: removeItem(scope.devices, value) };
      } else {
        scope = { mode: 'devices', group: '', devices: scope.mode === 'devices' ? addItem(scope.devices, value) : [value] };
        xdev = removeItem(xdev, value);
      }
      run();
      return;
    }
    let next = filters;
    if (f.domain) next = { ...filters, [f.param]: exclude ? domainExclude(filters[f.param] ?? [], domainOf(f), value) : domainInclude(filters[f.param] ?? [], value) };
    else if (exclude && f.exclude_param) next = excludeValue(filters, f.param, f.exclude_param, value);
    else if (!exclude) next = includeValue(filters, f.param, f.exclude_param, value);
    else return;
    setFilters(next);
    run();
  }

  function valueState(f: FieldDescriptor, value: string): 'in' | 'out' | '' {
    if (f.param === 'devices') {
      if (activeX.includes(value)) return 'out';
      return activeScope.mode === 'devices' && activeScope.devices.includes(value) ? 'in' : '';
    }
    const lc = (xs: string[] | undefined) => (xs ?? []).some((x) => x.toLowerCase() === value.toLowerCase());
    if (f.domain) {
      const s = activeF[f.param] ?? [];
      return !s.length ? '' : s.includes(value) ? 'in' : 'out';
    }
    if (lc(activeF[f.exclude_param])) return 'out';
    return lc(activeF[f.param]) ? 'in' : '';
  }

  const chips = $derived.by((): Chip[] => {
    const out: Chip[] = [];
    const chip = (key: string, text: string, title: string, excluded: boolean, remove: () => void) => out.push({ key, text, title, excluded, remove: () => (remove(), run()) });
    if (!fixed && scope.mode === 'devices')
      for (const d of scope.devices)
        chip(`dev:${d}`, deviceName(d), `Exporter ${d}`, false, () => {
          const rest = removeItem(scope.devices, d);
          scope = rest.length ? { ...scope, devices: rest } : allScope();
        });
    for (const d of xdev) chip(`xdev:${d}`, `not ${deviceName(d)}`, `Leaving out exporter ${d}`, true, () => (xdev = removeItem(xdev, d)));
    for (const f of schema?.fields ?? []) {
      if (f.param === 'devices' || !f.domain) continue;
      for (const c of domainChips(filters[f.param] ?? [], domainOf(f)))
        chip(`${f.param}:${c.value}`, `${c.included ? '' : 'not '}${f.domain.find((d) => d.value === c.value)?.label ?? c.value}`, `${f.label} ${c.value}`, !c.included,
          () => setFilters({ ...filters, [f.param]: domainRemove(filters[f.param] ?? [], domainOf(f), c.value, c.included) }));
    }
    const domainParams = new Set((schema?.fields ?? []).filter((f) => f.domain).map((f) => f.param));
    for (const def of FLOW_FILTERS) {
      if (domainParams.has(def.param)) continue;
      for (const v of filters[def.param] ?? []) chip(`${def.param}:${v}`, `${def.label.toLowerCase()} ${v}`, `${def.label} ${v}`, false, () => setFilters(removeValue(filters, def.param, v)));
      if (def.exclude)
        for (const v of filters[def.exclude] ?? [])
          chip(`${def.exclude}:${v}`, `not ${def.label.toLowerCase()} ${v}`, `Leaving out ${def.label.toLowerCase()} ${v}`, true, () => setFilters(removeValue(filters, def.exclude, v)));
    }
    return out;
  });

  /** Top rows add their keys to the filters and search again. */
  function addFromTop(add: Record<string, string[]>) {
    let next = { ...filters };
    for (const [k, vs] of Object.entries(add)) for (const v of vs) next = includeValue(next, k, FLOW_FILTERS.find((d) => d.param === k)?.exclude ?? '', v);
    setFilters(next);
    run();
  }

  // ----- saved searches (type=flow: the shared keys and the flow filters) -----
  function savedQuery() {
    return {
      devices: scope.mode === 'devices' ? [...scope.devices] : [],
      group: scope.mode === 'group' ? scope.group : '',
      ungrouped: scope.mode === 'ungrouped',
      exclude_devices: [...xdev],
      order,
      range: range.preset === 'custom' ? { from: range.from, to: range.to } : { last: range.preset },
      ...cleanFilters(filters),
    };
  }
  const canon = (o: Record<string, unknown>) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));
  const changed = $derived(!!savedCur && canon(savedQuery()) !== canon(savedOf(savedCur)));
  function savedOf(s: SavedSearch) {
    const f = formOfSaved(s.query);
    return {
      devices: f.scope.mode === 'devices' ? f.scope.devices : [],
      group: f.scope.mode === 'group' ? f.scope.group : '',
      ungrouped: f.scope.mode === 'ungrouped',
      exclude_devices: s.query.exclude_devices ?? [],
      order: f.order,
      range: f.range.preset === 'custom' ? { from: f.range.from, to: f.range.to } : { last: f.range.preset },
      ...cleanFilters(filtersOfSaved(s.query, FLOW_PARAMS)),
    };
  }
  function openSaved(s: SavedSearch) {
    const f = formOfSaved(s.query);
    scope = f.scope;
    range = f.range;
    order = f.order;
    xdev = [...(s.query.exclude_devices ?? [])];
    setFilters(filtersOfSaved(s.query, FLOW_PARAMS));
    savedCur = s;
    getSavedSearch(s.id).then((r) => savedCur?.id === s.id && (savedEtag = r.etag)).catch(() => {});
    go('events', toQuery());
  }
  function linkOf(s: SavedSearch): string {
    const f = formOfSaved(s.query);
    const p = new URLSearchParams();
    typeToQuery(FLOW, p);
    scopeToQuery(f.scope, p);
    rangeToQuery(f.range, p);
    extrasToQuery({ ...noExtras(), xdev: s.query.exclude_devices ?? [] }, p);
    filtersToQuery(filtersOfSaved(s.query, FLOW_PARAMS), p);
    if (f.order === 'asc') p.set('order', 'asc');
    p.set('saved', s.id);
    return `${location.origin}${location.pathname}${location.search}#/events?${p.toString()}`;
  }

  // ----- export these results -----
  function exportThese() {
    if (!active) return;
    const p = new URLSearchParams();
    scopeToQuery(activeScope, p);
    p.set('from', active.from!);
    p.set('to', active.to!);
    typeToQuery(FLOW, p);
    extrasToQuery({ ...noExtras(), xdev: activeX }, p);
    filtersToQuery(activeF, p);
    go('export', p.toString());
  }

  function zoom(from: string, to: string) {
    if (onzoom) return onzoom(from, to);
    range = { preset: 'custom', from, to };
    go('events', toQuery());
  }

  // ----- the record panel -----
  let open = $state<FlowResult | null>(null);
  $effect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && (open = null);
    addEventListener('keydown', esc);
    return () => removeEventListener('keydown', esc);
  });

  const spanText = $derived.by(() => {
    if (!summary) return '';
    const t = progressText(summary.progress, summary.partial);
    return t ? `${t}.` : "Counted every flow record in the window.";
  });
  const valueExtra = (v: FieldValueCount) => (v.bytes === undefined ? '' : dbytes(v.bytes));
  const histFmt = (n: number) => (hmetric === 'bytes' ? `${dbytes(n)} (exported)` : `${num(n)} flow record${n === 1 ? '' : 's'}`);
  const sampled = (r: FlowResult) => r.fields.sampling !== 1;
  const bytesText = (r: FlowResult) => (r.fields.bytes === null ? '–' : dbytes(r.fields.bytes));
  /** The scaled bytes beside a sampled record's exported ones ("≈ 2.2 MB"), or "". */
  const scaledText = (r: FlowResult) =>
    r.fields.bytes !== null && r.fields.bytes_scaled !== null && r.fields.bytes_scaled !== r.fields.bytes ? `≈ ${dbytes(r.fields.bytes_scaled)}` : '';
  const pktText = (r: FlowResult) => (r.fields.packets === null ? '–' : num(r.fields.packets));
</script>

<form class="card space-y-3" onsubmit={submit} role="search" aria-labelledby="fev-title">
  <div class="flex items-start gap-3">
    <div class="min-w-0 grow">
      <h1 id="fev-title" class="m-0 text-xl font-bold tracking-tight">Events</h1>
      <p class="mt-1 mb-0 text-[13.5px] text-muted">
        Every stored flow record, by flow time: a record shows when its traffic overlaps the range. Filter by address or prefix, port, protocol,
        interface, firewall or NAT event and rule, or click a value in Fields or Top. Flows have no text to search.
      </p>
    </div>
    <div class="seg typesw" role="radiogroup" aria-label="Data type">
      {#each types as t (t.type)}
        <button type="button" role="radio" aria-checked={t.type === FLOW} onclick={() => ontype(t.type)}>{t.label}</button>
      {/each}
    </div>
    {#if !fixed}
      <SavedMenu
        type={FLOW}
        current={savedCur}
        etag={savedEtag}
        query={savedQuery}
        {changed}
        {linkOf}
        onopen={openSaved}
        onsaved={(s, e) => ((savedCur = s), (savedEtag = e), setQuery((lastRun = toQuery())))}
        ondeleted={(id) => savedCur?.id === id && ((savedCur = null), setQuery((lastRun = toQuery())))}
      />
    {/if}
  </div>
  {#snippet box(d: (typeof FLOW_FILTERS)[number], param: string, label: string)}
    <label class="fld">
      <span class="flab">{label}</span>
      <input
        class="field font-mono"
        placeholder={d.placeholder}
        bind:value={boxes[param]}
        spellcheck="false"
        autocomplete="off"
        aria-invalid={!!boxErrors[param]}
        aria-describedby="fb-{param}"
        data-flow-filter={param}
      />
      {#if boxErrors[param]}<span id="fb-{param}" class="ferr" role="alert">{boxErrors[param]}</span>{/if}
    </label>
  {/snippet}
  <div class="flex flex-wrap items-start gap-2">
    {#each FLOW_FILTERS.filter((d) => d.main) as d (d.param)}{@render box(d, d.param, d.label)}{/each}
    <button type="submit" class="pill-btn self-end px-5 py-2"><Icon name="search" size={15} />Search</button>
  </div>
  <details class="more" bind:open={more}>
    <summary>More filters: firewall and NAT events, rule IDs, interfaces, domains, flags, and leaving values out</summary>
    <div class="mt-2 flex flex-wrap items-start gap-2">
      {#each FLOW_FILTERS.filter((d) => !d.main) as d (d.param)}{@render box(d, d.param, d.label)}{/each}
    </div>
    <div class="mt-2 flex flex-wrap items-start gap-2">
      {#each FLOW_FILTERS.filter((d) => d.exclude) as d (d.exclude)}{@render box(d, d.exclude, `Not ${d.label.toLowerCase()}`)}{/each}
    </div>
  </details>
  <div class="flex flex-wrap items-center gap-3">
    {#if !fixed}<DevicePicker bind:value={scope} />{/if}
    <div class="seg" role="radiogroup" aria-label="Order">
      <button type="button" role="radio" aria-checked={order === 'desc'} onclick={() => (order = 'desc')}>Newest first</button>
      <button type="button" role="radio" aria-checked={order === 'asc'} onclick={() => (order = 'asc')}>Oldest first</button>
    </div>
    {#if fixed}
      <span class="text-[13px] text-muted">The time range and the devices are the bundle's, above.</span>
    {:else}
      <TimeRange bind:value={range} error={rangeError} />
    {/if}
  </div>
</form>

<div class="evgrid">
  {#if schema}
    <FieldPanel
      fields={schema.fields}
      {summary}
      status={sumStatus}
      error={sumError}
      utc={prefs.utc}
      {chips}
      state={valueState}
      onpick={pick}
      oncontinue={countSummary}
      unit="flow"
      {spanText}
      {valueExtra}
    />
  {/if}
  <section class="log-panel res flex min-w-0 flex-col overflow-hidden" aria-label="Flow records">
    <div class="bar px-[18px] py-2.5 font-sans text-[13px]">
      <div class="flex flex-wrap items-center gap-2">
        <b class="text-white">Flow records</b>
        <span class="grow"></span>
        {#if status === 'running'}<button type="button" class="tail-btn" onclick={cancel}>Cancel</button>{/if}
        <div class="mseg" role="radiogroup" aria-label="Histogram counts">
          <button type="button" role="radio" aria-checked={hmetric === 'flows'} onclick={() => setMetric('flows')}>Flows</button>
          <button type="button" role="radio" aria-checked={hmetric === 'bytes'} onclick={() => setMetric('bytes')}>Bytes</button>
        </div>
        <button type="button" class="tail-btn" aria-pressed={showTop} onclick={() => (showTop = !showTop)}>Top</button>
        <button type="button" class="tail-btn" onclick={exportThese} disabled={!active || !results.length} title="Open Export with these exporters, range and flow filters">
          <Icon name="export" size={14} />Export these results
        </button>
      </div>
      <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-log-dim" aria-live="polite">
        {#if active}
          {num(results.length)} record{results.length === 1 ? '' : 's'}{cursor ? '+' : ''} · {fixed && activeScope.mode === 'all' ? 'Every active device' : scopeLabel(activeScope)} ·
          {stamp(active.from!, prefs.utc)} → {stamp(active.to!, prefs.utc)}{prefs.utc ? ' UTC' : ''} · by flow time
        {/if}
        {#if summary && spanText && summary.partial}<span class="scan">{spanText}</span>{/if}
      </div>
    </div>
    {#if active}
      <Histogram
        hist={summary?.histogram ?? null}
        from={active.from!}
        to={active.to!}
        utc={prefs.utc}
        busy={sumStatus === 'running'}
        onselect={zoom}
        onpoint={onbundle}
        fmt={histFmt}
      />
      {#if showTop}
        <FlowTop
          from={active.from!}
          to={active.to!}
          scope={scopeParams(activeScope)}
          excludeDevices={activeX}
          filters={activeF}
          utc={prefs.utc}
          bind:view
          onpick={addFromTop}
        />
      {/if}
    {/if}
    <div class="fres res-body overflow-auto px-[18px] py-2">
      {#if results.length}
        <div class="frow head" aria-hidden="true">
          <span>Flow end</span><span>Exporter</span><span>Source → destination</span><span>Proto</span><span class="r">Packets</span><span class="r">Bytes</span><span>Event</span>
        </div>
      {/if}
      {#if error}
        <p class="m-0 py-6 text-center font-sans text-[var(--sev-err)]" role="alert">{error}</p>
      {:else if status === 'running' && !results.length}
        <p class="m-0 py-6 text-center font-sans text-log-dim">Searching…</p>
      {:else if (status === 'done' || status === 'cancelled') && !results.length}
        <p class="m-0 py-6 text-center font-sans text-log-dim">
          {status === 'cancelled' ? 'Cancelled before anything matched.' : 'No flow records in this range. Try a longer range or fewer filters.'}
        </p>
      {/if}
      {#each results as r (r.ref)}
        <div class="frow" role="button" tabindex="0" data-ref={r.ref} onclick={() => (open = r)} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), (open = r))}>
          <span class="t">{stamp(r.fields.end, prefs.utc)}</span>
          <span class="h">{deviceName(r.device_id)}</span>
          <span class="ep" title="{endpoint(r.fields.src, r.fields.src_port)} → {endpoint(r.fields.dst, r.fields.dst_port)}">{endpoint(r.fields.src, r.fields.src_port)} → {endpoint(r.fields.dst, r.fields.dst_port)}</span>
          <span>{protoName(r.fields.proto, r.fields.proto_name)}</span>
          <span class="r">{pktText(r)}</span>
          <span class="r" title={r.fields.bytes === null ? '' : amountText('bytes', r.fields.bytes, r.fields.bytes_scaled, { sampling: r.fields.sampling }) + (sampled(r) ? '' : ', unsampled')}
            >{bytesText(r)}{#if scaledText(r)}<span class="samp">&nbsp;{scaledText(r)}</span>{/if}</span
          >
          <span class="ev" class:den={r.fields.fw_event === 'denied'} title={eventNote(r.fields)}>{eventNote(r.fields)}</span>
        </div>
      {/each}
      {#if results.length && cursor}
        <div class="py-3 text-center font-sans">
          {#if status === 'running'}<span class="text-log-dim">Loading…</span>
          {:else}<button type="button" class="tail-btn" onclick={fetchPage}>{status === 'cancelled' ? 'Continue the scan' : `Load ${num(PAGE)} more`}</button>{/if}
        </div>
      {:else if results.length && status === 'done'}
        <p class="m-0 py-3 text-center font-sans text-[12.5px] text-log-dim">End of the range.</p>
      {/if}
    </div>
  </section>
</div>

{#if open}
  {@const f = open.fields}
  <div class="overlay" role="presentation" onclick={() => (open = null)}></div>
  <div class="ctx log-panel" role="dialog" aria-modal="true" aria-label="Flow record">
    <div class="bar flex flex-wrap items-center gap-2 px-[18px] py-3 font-sans text-[13px]">
      <b class="text-white">Flow record</b>
      <span class="text-log-dim">{deviceName(open.device_id)} · received {stamp(open.received, prefs.utc)}</span>
      <span class="grow"></span>
      {#if onbundle}
        {@const at = f.end}
        <button type="button" class="tail-btn" onclick={() => ((open = null), onbundle?.(at))}><Icon name="export" size={14} />Bundle around this</button>
      {/if}
      <button type="button" class="tail-btn" onclick={() => (open = null)} aria-label="Close (Esc)"><Icon name="x" size={14} /></button>
    </div>
    <div class="overflow-auto px-[18px] py-3 font-sans text-[13.5px]">
      <dl class="dkv">
        {#each detailRows(f) as [k, raw] (k)}
          {@const v = k === 'Start' || k === 'End' || k === 'Event time' ? `${stamp(raw, prefs.utc)}${prefs.utc ? ' UTC' : ''}` : raw}
          <dt>{k}</dt><dd class:font-mono={/\d/.test(v)}>{v}</dd>
        {/each}
      </dl>
      <h3 class="dh">Other fields</h3>
      {#if f.extras.length}
        <p class="m-0 mb-1 text-[12.5px] text-log-dim">Information elements without a column, as the exporter sent them (enterprise number:element ID=bytes in hex).</p>
        <ul class="ext">{#each f.extras as x, i (i)}<li class="font-mono">{extraText(x)}</li>{/each}</ul>
      {:else}
        <p class="m-0 text-log-dim">None.</p>
      {/if}
    </div>
  </div>
{/if}

<style>
  .evgrid {
    display: grid;
    gap: 16px;
    align-items: start;
    margin-top: 16px;
  }
  @media (min-width: 1100px) {
    .evgrid {
      grid-template-columns: 17.5rem minmax(0, 1fr);
    }
    .evgrid > :global(.fp) {
      position: sticky;
      top: 16px;
      max-height: calc(100vh - 32px);
    }
  }
  .typesw {
    align-self: center;
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
    white-space: nowrap;
  }
  .seg button[aria-checked='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
  .mseg {
    display: inline-flex;
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 999px;
    padding: 2px;
  }
  .mseg button {
    border: 0;
    background: transparent;
    color: var(--log-fg);
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 12.5px;
    cursor: pointer;
  }
  .mseg button[aria-checked='true'] {
    background: rgba(255, 255, 255, 0.16);
    font-weight: 600;
  }
  .fld {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex: 1 1 11rem;
    max-width: 18rem;
  }
  .flab {
    font-size: 12.5px;
    font-weight: 600;
    color: var(--muted);
  }
  .ferr {
    display: block;
    margin-top: 2px;
    font-size: 12.5px;
    font-weight: 500;
    color: var(--bad-fg);
  }
  .more summary {
    cursor: pointer;
    font-size: 13px;
    color: var(--muted);
  }
  .res {
    border-radius: 22px;
  }
  .res-body {
    max-height: calc(100vh - 160px);
    min-height: 240px;
  }
  .bar {
    background: var(--log-bar);
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  }
  .scan {
    color: var(--sev-warn);
  }
  .fres {
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--log-fg);
  }
  .frow {
    display: grid;
    grid-template-columns: 19ch 12ch minmax(0, 2.2fr) 5ch 6ch 18ch minmax(0, 1.4fr);
    gap: 0 14px;
    padding: 2px 4px;
    border-radius: 6px;
    cursor: pointer;
    align-items: baseline;
  }
  .frow > span {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .frow:hover,
  .frow:focus-visible {
    background: rgba(255, 255, 255, 0.07);
  }
  .frow.head {
    cursor: default;
    color: var(--log-dim);
    font-family: var(--font-sans);
    font-weight: 600;
    position: sticky;
    top: -8px;
    background: var(--log-bg, #11151b);
    z-index: 1;
  }
  .frow .t {
    color: var(--log-dim);
  }
  .frow .h {
    color: var(--log-host);
  }
  .r {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .samp {
    color: var(--sev-notice);
  }
  .frow > span.ev {
    color: var(--log-dim);
  }
  .ev.den {
    color: var(--sev-err);
    font-weight: 600;
  }
  .tail-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.18);
    background: transparent;
    color: var(--log-fg);
    cursor: pointer;
    font-size: 13px;
  }
  .tail-btn:hover:not(:disabled),
  .tail-btn[aria-pressed='true'] {
    background: rgba(255, 255, 255, 0.12);
  }
  .tail-btn:disabled {
    opacity: 0.45;
    cursor: default;
  }
  .overlay {
    position: fixed;
    inset: 0;
    z-index: 50;
    background: rgba(10, 12, 16, 0.45);
  }
  .ctx {
    position: fixed;
    z-index: 51;
    top: 24px;
    right: 24px;
    bottom: 24px;
    width: min(760px, calc(100vw - 48px));
    display: flex;
    flex-direction: column;
    border-radius: 22px;
    overflow: hidden;
    box-shadow: 0 30px 80px rgba(0, 0, 0, 0.45);
    color: var(--log-fg);
  }
  .dkv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 3px 16px;
    margin: 0 0 12px;
  }
  .dkv dt {
    color: var(--log-dim);
  }
  .dkv dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .dh {
    margin: 8px 0 4px;
    font-size: 14px;
    font-weight: 700;
    color: #fff;
  }
  .ext {
    margin: 0;
    padding-left: 18px;
  }
</style>

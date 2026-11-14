<script lang="ts">
  import {
    ApiError,
    ALL_SEVS,
    getContext,
    getDevices,
    getSavedSearch,
    getSchema,
    getSummary,
    search,
    SUMMARY_EXPIRED,
    isTrap,
    type AnyResult,
    type DataType,
    type FieldDescriptor,
    type SavedSearch,
    type SearchParams,
    type SearchResult,
    type SevKey,
    type SummaryParams,
    type SummaryResponse,
    type TrapResult,
  } from '../lib/api';
  import {
    SYSLOG,
    SYSLOG_SAVED_KEYS,
    TRAP,
    cleanFilters,
    excludeValue,
    includeValue,
    isFailure,
    pduLabel,
    removeValue,
    savedTypeFilters,
    statusLabel,
    ticks,
    trapTitle,
    typeFiltersFromQuery,
    typeFromQuery,
    typeToQuery,
    varbindLine,
    type TypeFilters,
  } from '../lib/traps';
  import { bytes, num, stamp } from '../lib/format';
  import { matcher } from '../lib/highlight';
  import { prefs } from '../lib/prefs.svelte';
  import { defaultRange, rangeFromQuery, rangeToQuery, resolveRange, type Range } from '../lib/range';
  import { go, router, setQuery } from '../lib/router.svelte';
  import { allScope, scopeFromQuery, scopeLabel, scopeParams, scopeToQuery, sevFromQuery, sevToQuery, type Scope } from '../lib/scope';
  import { addToList, fieldsFromQuery, fieldsToQuery, noFields, splitList, type FieldFilters } from '../lib/fields';
  import {
    addItem,
    appKey,
    differsFromSaved,
    domainChips,
    domainExclude,
    domainInclude,
    domainRemove,
    extrasFromQuery,
    extrasToQuery,
    facKeys,
    formOfSaved,
    hostKey,
    modeFromQuery,
    modeToQuery,
    noExtras,
    removeItem,
    savedQueryOf,
    type Chip,
    type EventsForm,
    type Extras,
    type Mode,
  } from '../lib/events';
  import { termsError } from '../lib/terms';
  import { sevClass, sevLabel } from '../lib/severity';
  import { deviceName, live } from '../lib/status.svelte';
  import { splitRaw } from '../lib/syslog';
  import DevicePicker from '../components/DevicePicker.svelte';
  import FieldPanel from '../components/FieldPanel.svelte';
  import Histogram from '../components/Histogram.svelte';
  import Icon from '../components/Icon.svelte';
  import ModeSwitch from '../components/ModeSwitch.svelte';
  import SavedMenu from '../components/SavedMenu.svelte';
  import SeverityChips from '../components/SeverityChips.svelte';
  import TimeRange from '../components/TimeRange.svelte';
  import LogText from '../components/LogText.svelte';
  import { openMenu } from '../lib/block.svelte';
  import { tip } from '../lib/logtext';

  const PAGE = 500;
  const HOST_MAX = 28;
  /** The Host and Program/tag columns fit their longest value, up to this many characters. */
  const FIELD_MAX = 24;
  /** The field panel keeps counting for this much scanning per query, then offers "Count the rest" (SPEC §10.1.1). */
  const COUNT_FOR_MS = 60_000;

  // ----- the form -----
  let q = $state('');
  let mode = $state<Mode>('text');
  let cs = $state(false);
  let scope = $state<Scope>(allScope());
  let range = $state<Range>(defaultRange());
  let sev = $state<SevKey[]>([...ALL_SEVS]);
  let order = $state<'desc' | 'asc'>('desc');
  let fields = $state<FieldFilters>(noFields());
  let extras = $state<Extras>(noExtras());
  let showRaw = $state(false);
  /** The data type (SPEC §11.1): syslog, or SNMP traps (type=trap in the URL; links without it open syslog). */
  let dtype = $state<string>(SYSLOG);
  /** A non-syslog type's own filters, by parameter name (trap_oid, status, …). */
  let tf = $state<TypeFilters>({});

  // ----- the saved search the form was opened from (SPEC §10.1.4) -----
  let savedCur = $state<SavedSearch | null>(null);
  let savedEtag = $state('');
  let savedNote = $state('');

  const form = (): EventsForm => ({
    q,
    mode,
    cs,
    scope: $state.snapshot(scope),
    range: $state.snapshot(range),
    sev: [...sev],
    order,
    app: fields.app,
    host: fields.host,
    exclude: fields.exclude,
    extras: $state.snapshot(extras),
  });
  const changed = $derived(
    !!savedCur &&
      (differsFromSaved(form(), savedCur.query) || (dtype !== SYSLOG && JSON.stringify(cleanFilters(tf)) !== JSON.stringify(savedTypeFilters(savedCur.query)))),
  );

  /** The saved query for the form: a trap search saves its own filters and none of syslog's (the server refuses them). */
  function savedQuery() {
    const q: Record<string, unknown> = savedQueryOf(form());
    if (dtype === SYSLOG) return q;
    for (const k of SYSLOG_SAVED_KEYS) delete q[k];
    return { ...q, ...cleanFilters(tf) };
  }

  // ----- the search behind the results (frozen, so "Load more" sends the same parameters) -----
  let active = $state<SearchParams | null>(null);
  let activeScope = $state<Scope>(allScope());
  let activeMode = $state<Mode>('text');
  let activeExtras = $state<Extras>(noExtras());
  let activeType = $state<string>(SYSLOG);
  let activeTf = $state<TypeFilters>({});
  let results = $state.raw<AnyResult[]>([]);
  let seen = new Set<string>();
  let cursor = $state('');
  let status = $state<'idle' | 'running' | 'done' | 'cancelled' | 'error'>('idle');
  let error = $state('');
  let qError = $state('');
  let exError = $state('');
  let rangeError = $state('');
  let scanned = $state({ bytes: 0, files: 0 });
  let ctrl: AbortController | null = null;
  let gen = 0;

  // ----- the field panel and histogram: one summary for the active search -----
  let schemas = $state<DataType[]>([]);
  /** The field panel's fields: the schema of the type being searched. */
  const schema = $derived(schemas.find((t) => t.type === dtype) ?? (dtype === SYSLOG ? (schemas.find((t) => t.default) ?? null) : null));
  let summary = $state.raw<SummaryResponse | null>(null);
  let sumStatus = $state<'idle' | 'running' | 'paused' | 'done' | 'error'>('idle');
  let sumError = $state('');
  let sumCursor = '';
  let sumCtrl: AbortController | null = null;
  let sumGen = 0;

  getSchema()
    .then((s) => (schemas = s.types))
    .catch((x) => (sumError = `Couldn't load the field list: ${(x as Error).message}`));

  // The type switch shows when the server has another type (SPEC §11.2.5): the SNMP listener is on, or some device has trap files.
  let trapFilesSeen = $state(false);
  getDevices({ limit: 1000, sort: 'last_heard', hidden: 'include' })
    .then((p) => (trapFilesSeen = p.devices.some((d) => d.types?.includes(TRAP))))
    .catch(() => {});
  const trapType = $derived(schemas.find((t) => t.type === TRAP));
  const showTypes = $derived(
    dtype !== SYSLOG ||
      (!!trapType &&
        (trapFilesSeen || !!live.status?.listeners.some((l) => l.proto === 'snmp') || !!live.devices?.some((d) => d.types?.includes(TRAP)))),
  );

  /** Switching type keeps the text, devices, range and order; the other type's filters don't apply, so they're cleared. */
  function setType(t: string) {
    if (t === dtype) return;
    dtype = t;
    tf = {};
    sev = [...ALL_SEVS];
    fields = { ...noFields(), exclude: fields.exclude };
    extras = { ...noExtras(), xdev: extras.xdev };
    savedCur = null;
    savedEtag = '';
    run();
  }

  function toQuery(): string {
    const p = new URLSearchParams();
    if (q) p.set('q', q);
    modeToQuery(mode, p);
    if (cs) p.set('cs', '1');
    scopeToQuery(scope, p);
    rangeToQuery(range, p);
    typeQuery(p, dtype, sev, fields, extras, tf);
    if (order === 'asc') p.set('order', 'asc');
    if (savedCur) p.set('saved', savedCur.id);
    return p.toString();
  }

  /** The type and its filters in the page URL: syslog's severities, program/tag, host and facility, or the other type's own. */
  function typeQuery(p: URLSearchParams, t: string, sv: SevKey[], fl: FieldFilters, ex: Extras, f: TypeFilters) {
    typeToQuery(t, p);
    if (t === SYSLOG) {
      sevToQuery(sv, p);
      fieldsToQuery(fl, p);
      extrasToQuery(ex, p);
      return;
    }
    fieldsToQuery({ app: '', host: '', exclude: fl.exclude }, p);
    extrasToQuery({ ...noExtras(), xdev: ex.xdev }, p);
    for (const k of Object.keys(f).sort()) if (f[k].length) p.set(k, f[k].join(','));
  }

  function fromQuery(s: string) {
    const p = new URLSearchParams(s);
    q = p.get('q') ?? '';
    mode = modeFromQuery(p);
    cs = p.get('cs') === '1';
    scope = scopeFromQuery(p);
    range = rangeFromQuery(p);
    sev = sevFromQuery(p);
    fields = fieldsFromQuery(p);
    extras = extrasFromQuery(p);
    order = p.get('order') === 'asc' ? 'asc' : 'desc';
    dtype = typeFromQuery(p);
    tf = dtype === SYSLOG ? {} : typeFiltersFromQuery(p);
    const id = p.get('saved') ?? '';
    if (!id) {
      savedCur = null;
      savedEtag = '';
    } else if (id !== savedCur?.id) loadSaved(id);
  }

  /** A link with saved=<id> (bookmarked, or Back): the URL carries the parameters; this fetches the name and ETag. */
  async function loadSaved(id: string) {
    try {
      const { saved, etag } = await getSavedSearch(id);
      savedCur = saved;
      savedEtag = etag;
      savedNote = '';
    } catch (x) {
      savedCur = null;
      savedNote = x instanceof ApiError && x.status === 404 ? 'That saved search was deleted; this is a copy of its search.' : (x as Error).message;
    }
  }

  // A bookmarked or shared link (#/events?q=…, or the old #/search?q=…) runs straight away.
  // Opening the page without one browses the last hour of everything: an empty text box
  // matches every stored message.
  let lastRun = '';
  let opened = false;
  $effect(() => {
    const s = router.query;
    if (s && s !== lastRun) {
      opened = true;
      fromQuery(s);
      run();
    } else if (!s && !opened) {
      opened = true;
      run();
    }
  });

  function cancel() {
    ctrl?.abort();
    gen++;
    if (status === 'running') status = 'cancelled';
  }

  function cancelSummary() {
    sumCtrl?.abort();
    sumGen++;
  }

  /** The Cancel button stops both scans; the field panel keeps what it counted and offers the rest. */
  function cancelAll() {
    cancel();
    if (sumStatus === 'running') {
      cancelSummary();
      sumStatus = summary?.next_cursor ? 'paused' : 'idle';
    }
  }

  async function run(e?: SubmitEvent) {
    e?.preventDefault();
    cancel();
    cancelSummary();
    qError = exError = rangeError = error = sumError = '';
    const { from, to } = resolveRange(range);
    if (!from || !to || !(Date.parse(from) < Date.parse(to))) {
      rangeError = '"From" must be before "To".';
      status = 'error';
      return;
    }
    if (mode === 'terms') {
      // The server says the same; checking here puts the message under the box at once.
      qError = termsError(q);
      exError = termsError(fields.exclude);
      if (qError || exError) {
        status = 'error';
        active = null;
        results = [];
        cursor = '';
        summary = null;
        sumStatus = 'idle';
        lastRun = toQuery();
        setQuery(lastRun);
        return;
      }
    }
    lastRun = toQuery();
    setQuery(lastRun);
    activeScope = $state.snapshot(scope);
    activeMode = mode;
    activeExtras = $state.snapshot(extras);
    activeType = dtype;
    activeTf = cleanFilters($state.snapshot(tf));
    const shared: SearchParams = {
      q,
      regex: mode === 'regex',
      case: cs,
      syntax: mode === 'terms' ? 'terms' : undefined,
      ...scopeParams(scope),
      from,
      to,
      exclude: fields.exclude,
      exclude_devices: [...extras.xdev],
      order,
      limit: PAGE,
    };
    active =
      dtype === SYSLOG
        ? {
            ...shared,
            severities: [...sev],
            app: splitList(fields.app),
            host: splitList(fields.host),
            facilities: facKeys(extras.fac),
            exclude_app: [...extras.xapp],
            exclude_host: [...extras.xhost],
          }
        : { ...shared, type: dtype, filters: activeTf };
    results = [];
    seen = new Set();
    cursor = '';
    scanned = { bytes: 0, files: 0 };
    summary = null;
    sumCursor = '';
    countSummary();
    await fetchPage();
  }

  /** One page: keeps asking while the server says the scan was partial, until it's full or cancelled. */
  async function fetchPage() {
    if (!active) return;
    const my = ++gen;
    ctrl = new AbortController();
    status = 'running';
    let got = 0;
    try {
      for (;;) {
        // After a partial scan, ask only for what this page still needs (limit may change per page).
        const res = await search({ ...active, limit: PAGE - got, cursor: cursor || undefined }, ctrl.signal);
        if (my !== gen) return;
        const fresh = res.results.filter((r) => !seen.has(r.ref));
        for (const r of fresh) seen.add(r.ref);
        if (fresh.length) results = results.concat(fresh);
        got += fresh.length;
        cursor = res.next_cursor;
        scanned = { bytes: scanned.bytes + res.scanned_bytes, files: scanned.files + res.scanned_files };
        if (!(res.partial && res.next_cursor) || got >= PAGE) break;
      }
      status = 'done';
    } catch (x) {
      if (my !== gen || (x as Error).name === 'AbortError') return;
      status = 'error';
      const m = (x as Error).message;
      const bad = x instanceof ApiError && x.status === 400;
      if (bad && m.startsWith('exclude: ')) exError = m.slice('exclude: '.length);
      else if (bad && active.regex && /regexp|regular expression/i.test(m)) qError = m;
      else if (bad && active.syntax === 'terms' && / at character \d+|Too many terms|nested deeper|longer than 4 KiB/.test(m)) qError = m;
      else error = m;
    }
  }

  /**
   * The field panel and histogram: asks with the cursor while the summary is partial, for up
   * to COUNT_FOR_MS of scanning, then stops and offers "Count the rest" (SPEC §10.1.5). Each
   * response carries the running totals, so it just replaces what's shown. A summary whose
   * counts the server dropped (400, expired) starts again once.
   */
  async function countSummary() {
    if (!active) return;
    cancelSummary();
    const my = sumGen;
    const c = new AbortController();
    sumCtrl = c;
    sumStatus = 'running';
    sumError = '';
    const { order: _o, limit: _l, cursor: _c, ...base } = active;
    const params: SummaryParams = base;
    let scannedMs = 0;
    let restarted = false;
    try {
      for (;;) {
        let res: SummaryResponse;
        try {
          res = await getSummary({ ...params, cursor: sumCursor || undefined }, c.signal);
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
        scannedMs += res.elapsed_ms;
        if (!(res.partial && res.next_cursor)) {
          sumStatus = 'done';
          return;
        }
        if (scannedMs >= COUNT_FOR_MS) {
          sumStatus = 'paused';
          return;
        }
      }
    } catch (x) {
      if (my !== sumGen || (x as Error).name === 'AbortError') return;
      sumStatus = 'error';
      const m = (x as Error).message;
      // The results show a query error under the box; the panel only points there.
      sumError = x instanceof ApiError && x.status === 400 ? `Counts unavailable: ${m}` : m;
    }
  }

  const hl = $derived(active ? matcher(active.q, !!active.regex, !!active.case, active.syntax === 'terms') : null);
  const hostCh = $derived.by(() => {
    let w = 8;
    for (const id of new Set(results.map((r) => r.device_id))) w = Math.max(w, deviceName(id).length);
    return Math.min(w, HOST_MAX);
  });
  const fieldCh = (pick: (r: SearchResult) => string, label: string) => {
    let w = label.length;
    for (const r of results) if (!isTrap(r)) w = Math.max(w, pick(r).length);
    return Math.min(w, FIELD_MAX);
  };
  const hnCh = $derived(fieldCh((r) => r.host ?? '', 'Host'));
  const apCh = $derived(fieldCh((r) => r.app ?? '', 'Program/tag'));
  /** The Trap column fits its longest name (or OID). */
  const trCh = $derived.by(() => {
    let w = 4;
    for (const r of results) if (isTrap(r)) w = Math.max(w, trapTitle(r.fields).length);
    return Math.min(w, 34);
  });
  const text = (r: SearchResult) => (showRaw ? r.raw : splitRaw(r.raw).body);
  /** A trap's line: its varbinds by name, or (Raw) the stored record. */
  const trapText = (r: TrapResult) => (showRaw ? r.raw : r.fields.varbinds.length ? varbindLine(r.fields.varbinds) : r.fields.error || '(no varbinds)');

  /** Clicking a Host or Program/tag value narrows the search to it. */
  function narrow(e: Event, kind: 'host' | 'app', v: string) {
    e.stopPropagation();
    if (kind === 'host') {
      fields.host = addToList(fields.host, v);
      extras.xhost = removeItem(extras.xhost, v, hostKey);
    } else {
      fields.app = addToList(fields.app, v);
      extras.xapp = removeItem(extras.xapp, v, appKey);
    }
    run();
  }

  // ----- the field panel's clicks: by the schema's parameter names -----
  const domainOf = (f: FieldDescriptor) => (f.domain ?? []).map((d) => d.value);
  const sevStrings = () => (sev.length === ALL_SEVS.length ? [] : sev.length ? sev.map(String) : ['none']);
  const sevFromStrings = (v: string[]): SevKey[] =>
    !v.length ? [...ALL_SEVS] : v.includes('none') ? [] : ALL_SEVS.filter((k) => v.includes(String(k)));
  const removeFromList = (s: string, v: string, key: (x: string) => string) => removeItem(splitList(s), v, key).join(', ');

  function pick(f: FieldDescriptor, value: string, exclude: boolean) {
    const param = exclude && f.exclude_param ? f.exclude_param : f.param;
    if (dtype !== SYSLOG && f.param !== 'devices') {
      // Another type's own field, by the schema alone: a closed field sends its selected values (or the
      // complement to leave one out); an open one adds the value to its parameter or to its exclude form.
      if (f.domain) {
        const cur = tf[f.param] ?? [];
        tf = cleanFilters({ ...tf, [f.param]: exclude ? domainExclude(cur, domainOf(f), value) : domainInclude(cur, value) });
      } else if (exclude && f.exclude_param) tf = excludeValue(tf, f.param, f.exclude_param, value);
      else if (!exclude) tf = includeValue(tf, f.param, f.exclude_param, value);
      else return;
      run();
      return;
    }
    switch (param) {
      case 'devices':
        scope = { mode: 'devices', group: '', devices: scope.mode === 'devices' ? addItem(scope.devices, value) : [value] };
        extras.xdev = removeItem(extras.xdev, value);
        break;
      case 'exclude_devices':
        extras.xdev = addItem(extras.xdev, value);
        if (scope.mode === 'devices' && scope.devices.includes(value) && scope.devices.length > 1) scope.devices = removeItem(scope.devices, value);
        break;
      case 'host':
        fields.host = addToList(fields.host, value);
        extras.xhost = removeItem(extras.xhost, value, hostKey);
        break;
      case 'exclude_host':
        extras.xhost = addItem(extras.xhost, value, hostKey);
        fields.host = removeFromList(fields.host, value, hostKey);
        break;
      case 'app':
        fields.app = addToList(fields.app, value);
        extras.xapp = removeItem(extras.xapp, value, appKey);
        break;
      case 'exclude_app':
        extras.xapp = addItem(extras.xapp, value, appKey);
        fields.app = removeFromList(fields.app, value, appKey);
        break;
      case 'severities':
        sev = sevFromStrings(exclude ? domainExclude(sevStrings(), domainOf(f), value) : domainInclude(sevStrings(), value));
        break;
      case 'facilities':
        extras.fac = exclude ? domainExclude(extras.fac, domainOf(f), value) : domainInclude(extras.fac, value);
        break;
      default:
        return; // a parameter this page doesn't know (a later data type)
    }
    run();
  }

  /** Whether a value is in the active search's filters ("in"), left out ("out"), or neither. */
  function valueState(f: FieldDescriptor, value: string): 'in' | 'out' | '' {
    if (activeType !== SYSLOG && f.param !== 'devices') {
      const lc = (xs: string[] | undefined) => (xs ?? []).some((x) => x.toLowerCase() === value.toLowerCase());
      if (f.domain) {
        const s = activeTf[f.param] ?? [];
        return !s.length ? '' : s.includes(value) ? 'in' : 'out';
      }
      if (lc(activeTf[f.exclude_param])) return 'out';
      return lc(activeTf[f.param]) ? 'in' : '';
    }
    switch (f.param) {
      case 'devices':
        if (activeExtras.xdev.includes(value)) return 'out';
        return activeScope.mode === 'devices' && activeScope.devices.includes(value) ? 'in' : '';
      case 'host':
        if (active?.exclude_host?.some((x) => hostKey(x) === hostKey(value))) return 'out';
        return active?.host?.some((x) => hostKey(x) === hostKey(value)) ? 'in' : '';
      case 'app':
        if (active?.exclude_app?.some((x) => appKey(x) === appKey(value))) return 'out';
        return active?.app?.some((x) => appKey(x) === appKey(value)) ? 'in' : '';
      case 'severities': {
        const s = active?.severities ?? [...ALL_SEVS];
        return s.length === ALL_SEVS.length ? '' : s.map(String).includes(value) ? 'in' : 'out';
      }
      case 'facilities': {
        const s = activeExtras.fac;
        return !s.length ? '' : s.includes(value) ? 'in' : 'out';
      }
    }
    return '';
  }

  /** The active filters the panel can set, as chips; a click removes one and searches again. */
  const chips = $derived.by((): Chip[] => {
    if (!schema) return [];
    const out: Chip[] = [];
    const desc = (k: string) => schema!.fields.find((f) => f.param === k || f.exclude_param === k);
    const label = (k: string, v: string) => desc(k)?.domain?.find((d) => d.value === v)?.label ?? v;
    const chip = (key: string, text: string, title: string, excluded: boolean, remove: () => void) =>
      out.push({ key, text, title, excluded, remove: () => (remove(), run()) });
    if (scope.mode === 'devices')
      for (const d of scope.devices)
        chip(`dev:${d}`, deviceName(d), `Device ${d}`, false, () => {
          const rest = removeItem(scope.devices, d);
          scope = rest.length ? { ...scope, devices: rest } : allScope();
        });
    for (const d of extras.xdev) chip(`xdev:${d}`, `not ${deviceName(d)}`, `Leaving out device ${d}`, true, () => (extras.xdev = removeItem(extras.xdev, d)));
    if (dtype !== SYSLOG) {
      // The other type's fields: labels from the domain, or from the field panel's counts (a trap OID's MIB name).
      const counted = (key: string, v: string) => summary?.fields.find((x) => x.key === key)?.values.find((x) => x.value === v)?.label ?? v;
      for (const f of schema.fields) {
        if (f.param === 'devices') continue;
        if (f.domain) {
          const cur = tf[f.param] ?? [];
          for (const c of domainChips(cur, domainOf(f))) {
            const lab = label(f.param, c.value);
            chip(`${f.param}:${c.value}`, `${c.included ? '' : 'not '}${lab}`, `${f.label} ${lab}`, !c.included,
              () => (tf = cleanFilters({ ...tf, [f.param]: domainRemove(tf[f.param] ?? [], domainOf(f), c.value, c.included) })));
          }
          continue;
        }
        for (const v of tf[f.param] ?? []) chip(`${f.param}:${v}`, counted(f.key, v), `${f.label} ${v}`, false, () => (tf = removeValue(tf, f.param, v)));
        if (f.exclude_param)
          for (const v of tf[f.exclude_param] ?? [])
            chip(`${f.exclude_param}:${v}`, `not ${counted(f.key, v)}`, `Leaving out ${f.label.toLowerCase()} ${v}`, true, () => (tf = removeValue(tf, f.exclude_param, v)));
      }
      return out;
    }
    for (const h of splitList(fields.host)) chip(`host:${h}`, h, `Host ${h}`, false, () => (fields.host = removeFromList(fields.host, h, hostKey)));
    for (const h of extras.xhost) chip(`xhost:${h}`, `not ${h}`, `Leaving out host ${h}`, true, () => (extras.xhost = removeItem(extras.xhost, h)));
    for (const a of splitList(fields.app)) chip(`app:${a}`, a, `Program/tag ${a}`, false, () => (fields.app = removeFromList(fields.app, a, appKey)));
    for (const a of extras.xapp) chip(`xapp:${a}`, `not ${a}`, `Leaving out program/tag ${a}`, true, () => (extras.xapp = removeItem(extras.xapp, a)));
    const fd = desc('facilities');
    if (fd)
      for (const c of domainChips(extras.fac, domainOf(fd)))
        chip(`fac:${c.value}`, `${c.included ? '' : 'not '}${label('facilities', c.value)}`, `Facility ${label('facilities', c.value)}`, !c.included, () => (extras.fac = domainRemove(extras.fac, domainOf(fd), c.value, c.included)));
    const sd = desc('severities');
    if (sd)
      for (const c of domainChips(sevStrings(), domainOf(sd)))
        chip(`sev:${c.value}`, `${c.included ? '' : 'not '}${label('severities', c.value)}`, `Severity ${label('severities', c.value)}`, !c.included, () => (sev = sevFromStrings(domainRemove(sevStrings(), domainOf(sd), c.value, c.included))));
    return out;
  });

  /** A drag across the histogram: the new range goes into the URL as a new history entry, so Back zooms out. */
  function zoom(from: string, to: string) {
    range = { preset: 'custom', from, to };
    go('events', toQuery());
  }

  // ----- saved searches -----
  function openSaved(s: SavedSearch) {
    const f = formOfSaved(s.query);
    q = f.q;
    mode = f.mode;
    cs = f.cs;
    scope = f.scope;
    range = f.range;
    sev = f.sev;
    order = f.order;
    fields = { app: f.app, host: f.host, exclude: f.exclude };
    extras = f.extras;
    dtype = s.type === TRAP ? TRAP : SYSLOG;
    tf = dtype === SYSLOG ? {} : savedTypeFilters(s.query);
    savedCur = s;
    savedNote = '';
    savedEtag = '';
    getSavedSearch(s.id).then((r) => savedCur?.id === s.id && (savedEtag = r.etag)).catch(() => {});
    go('events', toQuery());
  }

  function onSaved(s: SavedSearch, etag: string) {
    savedCur = s;
    savedNote = '';
    savedEtag = etag;
    if (!etag) getSavedSearch(s.id).then((r) => savedCur?.id === s.id && (savedEtag = r.etag)).catch(() => {});
    // The URL gains saved=<id> without searching again.
    lastRun = toQuery();
    setQuery(lastRun);
  }

  function onDeleted(id: string) {
    if (savedCur?.id !== id) return;
    savedCur = null;
    savedEtag = '';
    lastRun = toQuery();
    setQuery(lastRun);
  }

  /** The link that opens a saved search: its parameters and saved=<id>. */
  function linkOf(s: SavedSearch): string {
    const f = formOfSaved(s.query);
    const p = new URLSearchParams();
    if (f.q) p.set('q', f.q);
    modeToQuery(f.mode, p);
    if (f.cs) p.set('cs', '1');
    scopeToQuery(f.scope, p);
    rangeToQuery(f.range, p);
    const t = s.type === TRAP ? TRAP : SYSLOG;
    typeQuery(p, t, f.sev, { app: f.app, host: f.host, exclude: f.exclude }, f.extras, t === SYSLOG ? {} : savedTypeFilters(s.query));
    if (f.order === 'asc') p.set('order', 'asc');
    p.set('saved', s.id);
    return `${location.origin}${location.pathname}${location.search}#/events?${p.toString()}`;
  }

  // ----- context panel -----
  interface Ctx {
    ref: string;
    before: number;
    after: number;
    lines: AnyResult[];
    hit: number;
    atStart: boolean;
    atEnd: boolean;
    loading: boolean;
    error: string;
  }
  let ctx = $state<Ctx | null>(null);
  let ctxBox: HTMLDivElement | undefined = $state();

  async function openContext(ref: string, before = 50, after = 50) {
    const same = ctx?.ref === ref;
    ctx = {
      ref,
      before,
      after,
      lines: same ? ctx!.lines : [],
      hit: same ? ctx!.hit : -1,
      atStart: same ? ctx!.atStart : false,
      atEnd: same ? ctx!.atEnd : false,
      loading: true,
      error: '',
    };
    try {
      const res = await getContext(ref, before, after);
      if (ctx?.ref !== ref) return;
      ctx = { ...ctx, lines: res.lines, hit: res.hit_index, atStart: res.at_start, atEnd: res.at_end, loading: false };
      if (!same) requestAnimationFrame(() => ctxBox?.querySelector('.hit')?.scrollIntoView({ block: 'center' }));
    } catch (x) {
      if (ctx?.ref === ref) ctx = { ...ctx, loading: false, error: (x as Error).message };
    }
  }
  const ctxHit = $derived(ctx && ctx.hit >= 0 ? ctx.lines[ctx.hit] : undefined);
  const ctxTop = $derived(!!ctx?.atStart);
  const ctxBottom = $derived(!!ctx?.atEnd);

  $effect(() => {
    if (!ctx) return;
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') ctx = null;
    };
    addEventListener('keydown', esc);
    return () => removeEventListener('keydown', esc);
  });

  // ----- export these results -----
  function exportThese() {
    if (!active) return;
    // Same devices (groups stay groups), range and filters, so the zip holds what the search showed.
    const p = new URLSearchParams();
    scopeToQuery(activeScope, p); // "all devices" stays all (no dev= list)
    p.set('from', active.from!);
    p.set('to', active.to!);
    sevToQuery(active.severities ?? [...ALL_SEVS], p);
    if (active.q) p.set('q', active.q);
    modeToQuery(activeMode, p);
    if (active.case) p.set('cs', '1');
    fieldsToQuery({ app: (active.app ?? []).join(','), host: (active.host ?? []).join(','), exclude: active.exclude ?? '' }, p);
    extrasToQuery(activeExtras, p);
    go('export', p.toString());
  }

  function rowKey(e: KeyboardEvent, ref: string) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      openContext(ref);
    }
  }

  const placeholder = $derived(
    mode === 'regex'
      ? 'Regular expression (RE2), e.g. deny (tcp|udp)'
      : mode === 'terms'
        ? 'Terms, e.g. deny AND (tcp OR udp) NOT 10.0.0.1'
        : 'Browse every stored message; type to filter',
  );
</script>

<div class="space-y-4">
  <form class="card space-y-3" onsubmit={run} role="search" aria-labelledby="ev-title">
    <div class="flex items-start gap-3">
      <div class="min-w-0 grow">
        <h1 id="ev-title" class="m-0 text-xl font-bold tracking-tight">Events</h1>
        {#if dtype === SYSLOG}
          <p class="mt-1 mb-0 text-[13.5px] text-muted">Every stored message, including older compressed days. Leave the text empty to browse; filter by text, program/tag, host, device, time and severity, or click a value in Fields.</p>
        {:else}
          <p class="mt-1 mb-0 text-[13.5px] text-muted">Every stored SNMP trap and inform. Leave the text empty to browse; filter by text (it never matches the raw packet), device and time, or click a trap, version, status or community in Fields.</p>
        {/if}
      </div>
      {#if showTypes}
        <div class="seg typesw" role="radiogroup" aria-label="Data type">
          {#each schemas as t (t.type)}
            <button type="button" role="radio" aria-checked={dtype === t.type} onclick={() => setType(t.type)}>{t.label}</button>
          {/each}
        </div>
      {/if}
      <SavedMenu
        type={dtype}
        current={savedCur}
        etag={savedEtag}
        query={savedQuery}
        {changed}
        {linkOf}
        onopen={openSaved}
        onsaved={onSaved}
        ondeleted={onDeleted}
      />
    </div>
    {#if savedCur || savedNote}
      <div class="savedline" aria-live="polite">
        {#if savedCur}
          <span>Saved search <b>{savedCur.name}</b></span>
          {#if changed}<span class="badge" title="The form differs from the saved search; Saved, then Save, updates it">changed</span>{/if}
          {#if savedCur.missing_devices.length}
            <span class="missing">
              Devices no longer known:
              {#each savedCur.missing_devices as d, i (d)}{i ? ', ' : ''}<s title="No longer known; the search runs with the rest">{d}</s>{/each}
              {savedCur.missing_devices.length === (savedCur.query.devices?.length ?? 0) ? '(so it matches nothing)' : '(the search runs with the rest)'}
            </span>
          {/if}
          {#if savedCur.missing_group}<span class="missing">Group <s>{savedCur.query.group}</s> has no devices any more, so it matches nothing</span>{/if}
        {:else}<span class="text-muted">{savedNote}</span>{/if}
      </div>
    {/if}
    <div class="flex flex-wrap items-start gap-2">
      <div class="grow basis-80">
        <label class="sr-only" for="sq">Search text</label>
        <input
          id="sq"
          class="field font-mono"
          {placeholder}
          bind:value={q}
          spellcheck="false"
          autocomplete="off"
          aria-invalid={!!qError}
          aria-describedby="sq-err"
        />
        {#if qError}<p id="sq-err" class="ferr" role="alert">{qError}</p>{/if}
      </div>
      <ModeSwitch bind:value={mode} />
      <button type="button" class="toggle" aria-pressed={cs} onclick={() => (cs = !cs)} title="Match upper and lower case exactly">Aa Case</button>
      <button type="submit" class="pill-btn px-5 py-2"><Icon name="search" size={15} />Search</button>
    </div>
    <div class="flex flex-wrap items-start gap-2">
      {#if dtype === SYSLOG}
      <label class="fld">
        <span class="flab">Program/tag</span>
        <input
          class="field font-mono"
          placeholder="sshd, %FW-6-*"
          bind:value={fields.app}
          spellcheck="false"
          autocomplete="off"
          title="Programs or tags, comma-separated, any case. End with * for a prefix."
        />
      </label>
      <label class="fld">
        <span class="flab">Host</span>
        <input
          class="field font-mono"
          placeholder="web-01, edge-fw-01"
          bind:value={fields.host}
          spellcheck="false"
          autocomplete="off"
          title="Hostnames from the message header, comma-separated, any case"
        />
      </label>
      {/if}
      <label class="fld grow">
        <span class="flab">Exclude</span>
        <input
          class="field font-mono"
          placeholder={mode === 'regex' ? 'Regular expression to leave out' : mode === 'terms' ? 'Terms to leave out' : 'Text to leave out'}
          bind:value={fields.exclude}
          spellcheck="false"
          autocomplete="off"
          aria-invalid={!!exError}
          aria-describedby="ex-err"
          title="Lines matching this are left out. Terms, Regex and Case apply here too."
        />
        {#if exError}<span id="ex-err" class="ferr" role="alert">{exError}</span>{/if}
      </label>
    </div>
    <div class="flex flex-wrap items-center gap-3">
      <DevicePicker bind:value={scope} />
      <div class="seg" role="radiogroup" aria-label="Order">
        <button type="button" role="radio" aria-checked={order === 'desc'} onclick={() => (order = 'desc')}>Newest first</button>
        <button type="button" role="radio" aria-checked={order === 'asc'} onclick={() => (order = 'asc')}>Oldest first</button>
      </div>
      <!-- Last, so an open custom range gets its own line under the other controls. -->
      <TimeRange bind:value={range} error={rangeError} />
    </div>
    {#if dtype === SYSLOG}<div class="sevbar"><SeverityChips bind:value={sev} label="Search severities" /></div>{/if}
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
    />
  {:else if sumError}
    <aside class="log-panel fp-err" aria-label="Field values"><p class="m-0 p-4 font-sans text-[13px] text-[var(--sev-err)]" role="alert">{sumError}</p></aside>
  {/if}
  <section class="log-panel res flex min-w-0 flex-col overflow-hidden" aria-label="Results">
    <!-- Two rows, so the buttons stay on the first line beside the field panel: the title and the buttons, then
         what the results are and how much was scanned. -->
    <div class="bar px-[18px] py-2.5 font-sans text-[13px]">
      <div class="flex flex-wrap items-center gap-2">
        <b class="text-white">Results</b>
        <span class="grow"></span>
        {#if status === 'running'}<button type="button" class="tail-btn" onclick={cancelAll}>Cancel</button>{/if}
        <button type="button" class="tail-btn" aria-pressed={prefs.wrap} onclick={() => (prefs.wrap = !prefs.wrap)}>Wrap</button>
        <button
          type="button"
          class="tail-btn"
          aria-pressed={showRaw}
          onclick={() => (showRaw = !showRaw)}
          title={activeType === SYSLOG ? 'Show the PRI and syslog header too' : 'Show the stored record (every key, and the packet as base64)'}>Raw</button
        >
        <button
          type="button"
          class="tail-btn"
          onclick={exportThese}
          disabled={!active || !results.length || activeType !== SYSLOG}
          title={activeType === SYSLOG
            ? 'Open Export with these devices, range, severities, text, program/tag, host, facility and exclude filters'
            : 'The Export page exports syslog only in this version; woodshed search --type trap exports traps from the command line'}
        >
          <Icon name="export" size={14} />Export these results
        </button>
      </div>
      <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5">
        <span class="text-log-dim" aria-live="polite">
          {#if status === 'idle'}Leave the text empty to browse every stored message, or type to filter.
          {:else if active}
            {num(results.length)} line{results.length === 1 ? '' : 's'}{cursor ? '+' : ''} · {scopeLabel(activeScope)} · {stamp(
              active.from!,
              prefs.utc,
            )} → {stamp(active.to!, prefs.utc)}{prefs.utc ? ' UTC' : ''}
          {/if}
        </span>
        {#if status === 'running'}
          <span class="scan" role="status"><span class="spin" aria-hidden="true"></span>Scanned {bytes(scanned.bytes)} in {num(scanned.files)} file{scanned.files === 1 ? '' : 's'}…</span>
        {:else if status !== 'idle'}
          <span class="text-log-dim">Scanned {bytes(scanned.bytes)} in {num(scanned.files)} file{scanned.files === 1 ? '' : 's'}</span>
        {/if}
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
      />
    {/if}

    <div
      class="logview fields res-body overflow-auto px-[18px] py-2"
      class:nowrap={!prefs.wrap}
      style:--hostw="{hostCh}ch"
      style:--tw="18ch"
      style:--hnw="{hnCh}ch"
      style:--apw="{apCh}ch"
      style:--trw="{trCh}ch"
    >
      {#if results.length && activeType !== SYSLOG}
        <div class="logline colhead trap" aria-hidden="true">
          <span class="c t">Time</span><span class="c h">Device</span><span class="c tr">Trap</span><span class="m">Varbinds</span>
        </div>
      {:else if results.length}
        <div class="logline colhead" aria-hidden="true">
          <span class="c t">Time</span><span class="c h">Device</span><span class="c hn">Host</span><span class="c ap">Program/tag</span><span class="c s">Level</span><span class="m">Message</span>
        </div>
      {/if}
      {#if error}
        <p class="m-0 py-6 text-center font-sans text-[var(--sev-err)]" role="alert">{error}</p>
      {:else if qError || exError}
        <p class="m-0 py-6 text-center font-sans text-log-dim">{mode === 'terms' ? 'Fix the terms above and search again.' : 'Fix the regular expression above and search again.'}</p>
      {:else if status === 'running' && !results.length}
        <p class="m-0 py-6 text-center font-sans text-log-dim">Searching…</p>
      {:else if (status === 'done' || status === 'cancelled') && !results.length}
        <p class="m-0 py-6 text-center font-sans text-log-dim">
          {status === 'cancelled'
            ? 'Cancelled before anything matched.'
            : activeType === SYSLOG && !active?.severities?.length
              ? 'No levels selected, so nothing matches. Pick some severities above.'
              : 'No matches in this range. Try a longer range, fewer filters, or other words.'}
        </p>
      {/if}
      {#each results as r (r.ref)}
        {#if isTrap(r)}
          <div
            class="logline clickable trap"
            role="button"
            tabindex="0"
            data-ref={r.ref}
            title={r.raw}
            aria-label="Show the decoded trap and the traps around it"
            onclick={() => openContext(r.ref)}
            oncontextmenu={(e) => { e.preventDefault(); openMenu(r.device_id, e.clientX, e.clientY); }}
            onkeydown={(e) => rowKey(e, r.ref)}
          >
            <span class="c t">{stamp(r.received, prefs.utc)}</span><span class="c h">{deviceName(r.device_id)}</span><span
              class="c tr"
              class:bad={isFailure(r.fields.status)}
              title={r.fields.trap_oid || statusLabel(r.fields.status)}>{trapTitle(r.fields)}</span
            ><span class="m"><LogText text={trapText(r)} re={hl} raw={showRaw} /></span>
          </div>
        {:else}
        <div
          class="logline clickable"
          role="button"
          tabindex="0"
          data-ref={r.ref}
          title={tip(r.raw)}
          aria-label="Show the lines around this one"
          onclick={() => openContext(r.ref)}
          oncontextmenu={(e) => { e.preventDefault(); openMenu(r.device_id, e.clientX, e.clientY); }}
          onkeydown={(e) => rowKey(e, r.ref)}
        >
          <span class="c t">{stamp(r.received, prefs.utc)}</span><span class="c h">{deviceName(r.device_id)}</span
          >{#if r.host}<button
              type="button"
              class="c hn cell"
              title="Show only host {r.host}"
              onclick={(e) => narrow(e, 'host', r.host)}
              onkeydown={(e) => e.stopPropagation()}>{r.host}</button
            >{:else}<span class="c hn none">–</span>{/if}{#if r.app}<button
              type="button"
              class="c ap cell"
              title="Show only {r.app}"
              onclick={(e) => narrow(e, 'app', r.app)}
              onkeydown={(e) => e.stopPropagation()}>{r.app}</button
            >{:else}<span class="c ap none">–</span>{/if}<span class="c s {sevClass(r.severity)}">{sevLabel(r.severity)}</span
          ><span class="m"><LogText text={text(r)} re={hl} raw={showRaw} /></span>
        </div>
        {/if}
      {/each}
      {#if results.length && cursor}
        <div class="py-3 text-center font-sans">
          {#if status === 'running'}
            <span class="text-log-dim">Loading…</span>
          {:else}
            <button type="button" class="tail-btn" onclick={fetchPage}>{status === 'cancelled' ? 'Continue the scan' : `Load ${num(PAGE)} more`}</button>
          {/if}
        </div>
      {:else if results.length && status === 'done'}
        <p class="m-0 py-3 text-center font-sans text-[12.5px] text-log-dim">End of the range.</p>
      {/if}
    </div>
  </section>
  </div>
</div>

{#if ctx}
  <div class="overlay" role="presentation" onclick={() => (ctx = null)}></div>
  <div class="ctx log-panel" role="dialog" aria-modal="true" aria-label="Lines around the result">
    <div class="bar flex flex-wrap items-center gap-2 px-[18px] py-3 font-sans text-[13px]">
      <b class="text-white">{ctxHit && isTrap(ctxHit) ? 'Trap' : 'Context'}</b>
      {#if ctxHit}<span class="text-log-dim">{deviceName(ctxHit.device_id)} · {stamp(ctxHit.received, prefs.utc)} · {ctx.before} before, {ctx.after} after</span>{/if}
      <span class="grow"></span>
      <button type="button" class="tail-btn" aria-pressed={prefs.wrap} onclick={() => (prefs.wrap = !prefs.wrap)}>Wrap</button>
      <button type="button" class="tail-btn" onclick={() => (ctx = null)} aria-label="Close (Esc)"><Icon name="x" size={14} /></button>
    </div>
      {#if ctxHit && isTrap(ctxHit)}
      {@const tr = ctxHit.fields}
      <section class="decoded font-sans mx-[18px] mt-3" aria-label="The decoded trap">
        <h3 class="dh">
          {trapTitle(tr)}
          <span class="sub">{pduLabel(tr)} from {deviceName(ctxHit.device_id)}{tr.cred ? ` · ${tr.cred.startsWith('#') ? 'community' : 'user'} ${tr.cred}` : ''}</span>
        </h3>
        <dl class="dkv">
          {#if tr.trap_oid}<dt>Trap OID</dt><dd class="font-mono">{tr.trap_oid}{tr.trap_name ? ` (${tr.trap_name})` : ''}</dd>{/if}
          <dt>Status</dt>
          <dd class:bad={isFailure(tr.status)}>{statusLabel(tr.status)}{tr.error ? `: ${tr.error}` : ''}</dd>
          {#if tr.uptime !== null}<dt>Device uptime</dt><dd>{ticks(tr.uptime)} <span class="text-log-dim">({tr.uptime} ticks)</span></dd>{/if}
          {#if tr.enterprise}<dt>Enterprise</dt><dd class="font-mono">{tr.enterprise}</dd>{/if}
          {#if tr.generic !== null}<dt>Generic / specific</dt><dd>{tr.generic} / {tr.specific}</dd>{/if}
          {#if tr.dup}<dt>Retransmitted</dt><dd>yes: the same inform arrived again within 60 s, so it's stored again</dd>{/if}
        </dl>
        {#if tr.varbinds.length}
          <table class="vbt">
            <thead><tr><th scope="col">Name</th><th scope="col">OID</th><th scope="col">Type</th><th scope="col">Value</th></tr></thead>
            <tbody>
              {#each tr.varbinds as v, k (k)}
                <tr>
                  <td class="font-mono">{v.name || '–'}</td>
                  <td class="font-mono text-log-dim">{v.oid}</td>
                  <td class="text-log-dim">{v.type}</td>
                  <td class="font-mono">{v.value}{#if v.value_name}<span class="text-log-dim"> ({v.value_name})</span>{/if}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="m-0 mt-2 text-[13px] text-log-dim">
            {isFailure(tr.status) ? 'No varbinds: only the parts readable without the keys are stored for a failed or broken packet.' : 'No varbinds.'}
          </p>
        {/if}
        <p class="m-0 mt-2 text-[12.5px] text-log-dim">Names come from the MIBs loaded now. Below: this device's traps around it.</p>
      </section>
    {/if}
    <div bind:this={ctxBox} class="logview min-h-0 grow overflow-auto px-[18px] py-2" class:nowrap={!prefs.wrap} style:--hostw="{hostCh}ch" style:--tw="18ch" style:--trw="{trCh}ch">
      {#if ctx.error}<p class="font-sans text-[var(--sev-err)]" role="alert">{ctx.error}</p>{/if}
      <div class="py-1 text-center font-sans">
        <button
          type="button"
          class="tail-btn"
          disabled={ctx.loading || ctx.before >= 500 || ctxTop}
          onclick={() => ctx && openContext(ctx.ref, Math.min(500, ctx.before + 50), ctx.after)}
        >
          {ctxTop ? 'Start of the stored log' : 'Show 50 more above'}
        </button>
      </div>
      {#if ctx.loading && !ctx.lines.length}<p class="font-sans text-log-dim">Loading…</p>{/if}
      {#each ctx.lines as l, i (l.ref)}
        {#if isTrap(l)}
          <div class="logline trap" class:hit={i === ctx.hit} title={l.raw}>
            <span class="c t">{stamp(l.received, prefs.utc)}</span><span class="c h">{deviceName(l.device_id)}</span><span class="c tr" class:bad={isFailure(l.fields.status)}
              >{trapTitle(l.fields)}</span
            ><span class="m"><LogText text={trapText(l)} re={i === ctx.hit ? hl : null} raw={showRaw} /></span>
          </div>
        {:else}
        <div class="logline" class:hit={i === ctx.hit} title={tip(l.raw)}>
          <span class="c t">{stamp(l.received, prefs.utc)}</span><span class="c h">{deviceName(l.device_id)}</span><span class="c s {sevClass(l.severity)}"
            >{sevLabel(l.severity)}</span
          ><span class="m"><LogText text={text(l)} re={i === ctx.hit ? hl : null} raw={showRaw} /></span>
        </div>
        {/if}
      {/each}
      <div class="py-1 text-center font-sans">
        <button
          type="button"
          class="tail-btn"
          disabled={ctx.loading || ctx.after >= 500 || ctxBottom}
          onclick={() => ctx && openContext(ctx.ref, ctx.before, Math.min(500, ctx.after + 50))}
        >
          {ctxBottom ? 'Newest stored line' : 'Show 50 more below'}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .evgrid {
    display: grid;
    gap: 16px;
    align-items: start;
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
  @media (max-width: 1099px) {
    .evgrid > :global(.fp) {
      order: 2;
    }
  }
  .typesw {
    align-self: center;
  }
  .typesw button {
    white-space: nowrap;
  }
  /* Trap rows: time, device, trap name (or OID), then the varbinds, with the same hanging indent as syslog rows. */
  :global(.logview .logline.trap) {
    --msgx: calc(var(--tw, 12ch) + var(--hostw, 12ch) + var(--trw, 20ch) + 3.6ch);
  }
  :global(.logline > .c.tr) {
    width: var(--trw, 20ch);
    color: var(--log-fg);
    font-weight: 600;
  }
  .bad {
    color: var(--sev-err) !important;
  }
  .decoded {
    flex: none;
    max-height: 45%;
    overflow: auto;
    margin-bottom: 6px;
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid rgba(255, 255, 255, 0.14);
    background: rgba(255, 255, 255, 0.04);
    color: var(--log-fg);
    font-size: 13.5px;
  }
  .dh {
    margin: 0 0 8px;
    font-size: 15px;
    font-weight: 700;
    color: #fff;
  }
  .dh .sub {
    margin-left: 8px;
    font-weight: 400;
    font-size: 12.5px;
    color: var(--log-dim);
  }
  .dkv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 2px 14px;
    margin: 0 0 8px;
  }
  .dkv dt {
    color: var(--log-dim);
  }
  .dkv dd {
    margin: 0;
    min-width: 0;
    overflow-wrap: anywhere;
  }
  .vbt {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  .vbt th {
    text-align: left;
    font-weight: 600;
    color: var(--log-dim);
    padding: 3px 10px 3px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.12);
  }
  .vbt td {
    padding: 3px 10px 3px 0;
    vertical-align: top;
    overflow-wrap: anywhere;
  }
  .savedline {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 10px;
    font-size: 13px;
  }
  .badge {
    padding: 1px 8px;
    border-radius: 999px;
    background: var(--warn-bg);
    border: 1px solid var(--warn-border);
    color: var(--warn-fg);
    font-size: 12px;
    font-weight: 600;
  }
  .missing {
    color: var(--muted);
  }
  .missing s {
    font-family: var(--font-mono);
  }
  .toggle {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 8px 12px;
    border-radius: 12px;
    border: 1px solid var(--input-border);
    background: var(--input);
    color: var(--fg);
    font-size: 13px;
    font-family: var(--font-mono);
    cursor: pointer;
    white-space: nowrap;
  }
  .toggle[aria-pressed='true'] {
    background: var(--btn);
    color: var(--btn-fg);
    border-color: var(--btn);
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
  .sevbar {
    display: inline-flex;
    padding: 6px 10px;
    border-radius: 14px;
    background: var(--log-bar);
    border: 1px solid var(--log-border);
  }
  .fld {
    display: flex;
    flex-direction: column;
    gap: 3px;
    flex-basis: 13rem;
  }
  .fld.grow {
    flex-grow: 1;
    flex-basis: 16rem;
  }
  .flab {
    font-size: 12.5px;
    font-weight: 600;
    color: var(--muted);
  }
  .ferr {
    display: block;
    margin: 4px 0 0;
    font-size: 13px;
    font-weight: 500;
    color: var(--bad-fg);
    font-family: var(--font-mono);
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
  .scan {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    color: var(--sev-warn);
  }
  .spin {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid rgba(255, 255, 255, 0.2);
    border-top-color: var(--sev-warn);
    animation: spin 0.9s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
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
    width: min(1200px, calc(100vw - 48px));
    display: flex;
    flex-direction: column;
    border-radius: 22px;
    overflow: hidden;
    box-shadow: 0 30px 80px rgba(0, 0, 0, 0.45);
  }
</style>

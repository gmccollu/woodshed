<script lang="ts">
  import {
    ALL_SEVS,
    createExport,
    deleteExport,
    estimateExport,
    ApiError,
    downloadsViaTransport,
    exportDownloadUrl,
    exportTicket,
    getSchema,
    listExports,
    transportDownload,
    type DataType,
    type ExportEstimate,
    type ExportInfo,
    type ExportRequest,
    type SevKey,
  } from '../lib/api';
  import { ago, bytes, num, remaining, stamp } from '../lib/format';
  import { prefs } from '../lib/prefs.svelte';
  import { defaultRange, rangeFromQuery, resolveRange, type Range } from '../lib/range';
  import { router } from '../lib/router.svelte';
  import { scopeFromQuery, sevFromQuery, type Scope } from '../lib/scope';
  import { fieldsFromQuery, noFields, splitList, type FieldFilters } from '../lib/fields';
  import { extrasFromQuery, facKeys, hasExtras, modeFromQuery, noExtras, type Extras, type Mode } from '../lib/events';
  import { deviceName, groupSize, live, ungroupedCount } from '../lib/status.svelte';
  import { SEVERITIES } from '../lib/severity';
  import { SYSLOG, TRAP, typeFiltersFromQuery, typeFromQuery, type TypeFilters } from '../lib/traps';
  import { bundleFromQuery, bundleTitle, bundleToQuery, bundleWindow, isBundle, newBundle, rfc3339, typesText, type BundleForm } from '../lib/bundle';
  import { go } from '../lib/router.svelte';
  import BundleBuild from '../components/BundleBuild.svelte';
  import BundleTypes from '../components/BundleTypes.svelte';
  import BundleWindow from '../components/BundleWindow.svelte';
  import DevicePicker from '../components/DevicePicker.svelte';
  import ModeSwitch from '../components/ModeSwitch.svelte';
  import Icon from '../components/Icon.svelte';
  import SeverityChips from '../components/SeverityChips.svelte';
  import TimeRange from '../components/TimeRange.svelte';

  const DAY = 86_400_000;

  // ----- the form; "Export these results" on Events fills it through the URL -----
  let scope = $state<Scope>({ mode: 'all', group: '', devices: [] });
  let range = $state<Range>(defaultRange());
  let sev = $state<SevKey[]>([...ALL_SEVS]);
  let q = $state('');
  let mode = $state<Mode>('text');
  let cs = $state(false);
  let fields = $state<FieldFilters>(noFields());
  /** Facility and the exclude forms of device, program/tag and host: set only from Events' field panel. */
  let extras = $state<Extras>(noExtras());
  let fromSearch = $state(false);
  /** 1.2: the data types of a plain export (SPEC §11.7): syslog, SNMP traps, or both (then without filters). */
  let xtype = $state<'syslog' | 'trap' | 'both'>('syslog');
  /** The trap filters, from Events' "Export these results" on traps (by parameter name). */
  let trapF = $state<TypeFilters>({});

  // ----- the two ways to export: a time range, or around a moment (the incident bundle, SPEC §11.3) -----
  let tab = $state<'range' | 'around'>('range');
  let bform = $state<BundleForm>(newBundle(rfc3339(Math.floor(Date.now() / 60_000) * 60_000)));
  const bError = $derived.by(() => {
    const w = bundleWindow(bform.at, bform.before, bform.after);
    if (typeof w === 'string') return w;
    if (bform.scope.mode === 'devices' && !bform.scope.devices.length) return 'Pick at least one device, or every device active in the window.';
    return '';
  });
  /** The preview: Events over the bundle's window and devices, with its own Build the bundle. */
  function preview() {
    const p = new URLSearchParams();
    bundleToQuery($state.snapshot(bform) as BundleForm, p);
    if (bform.types.length === 1 && bform.types[0] !== SYSLOG) p.set('type', bform.types[0]);
    go('events', p.toString());
  }

  let schemas = $state<DataType[]>([]);
  getSchema()
    .then((s) => (schemas = s.types))
    .catch(() => {});
  const hasTraps = $derived(schemas.some((t) => t.type === TRAP));

  $effect(() => {
    const s = router.query;
    if (!s) return;
    const p = new URLSearchParams(s);
    const b = bundleFromQuery(p);
    if (b) {
      tab = 'around';
      bform = b;
      return;
    }
    tab = 'range';
    const t = typeFromQuery(p);
    xtype = t === TRAP ? 'trap' : 'syslog';
    trapF = t === TRAP ? typeFiltersFromQuery(p) : {};
    scope = scopeFromQuery(p);
    range = rangeFromQuery(p);
    sev = sevFromQuery(p);
    q = p.get('q') ?? '';
    mode = modeFromQuery(p);
    cs = p.get('cs') === '1';
    fields = fieldsFromQuery(p);
    extras = extrasFromQuery(p);
    fromSearch = true;
  });

  // How many devices the scope covers (from /api/devices and /api/groups totals).
  const count = $derived(
    scope.mode === 'devices'
      ? scope.devices.length
      : scope.mode === 'all'
        ? live.deviceTotal
        : scope.mode === 'group'
          ? groupSize(scope.group)
          : ungroupedCount(),
  );
  const formError = $derived(
    count === 0 ? 'Pick at least one device.' : xtype === 'syslog' && !sev.length ? 'Pick at least one severity, or All.' : '',
  );


  // Groups stay groups (the server resolves them when it builds); "all devices" is sent as the list.
  async function request(): Promise<ExportRequest> {
    const { from, to } = resolveRange(range);
    const who =
      scope.mode === 'group'
        ? { group: scope.group }
        : scope.mode === 'ungrouped'
          ? { ungrouped: true }
          : scope.mode === 'all'
            ? { all_devices: true }
            : { devices: scope.devices };
    // Both types: every line in range (filters apply to one type). Traps: the text, exclude and trap filters.
    if (xtype === 'both') return { ...who, from, to, types: [SYSLOG, TRAP], exclude_devices: extras.xdev };
    if (xtype === 'trap')
      return {
        ...who,
        from,
        to,
        types: [TRAP],
        q: q.trim(),
        regex: mode === 'regex',
        syntax: mode === 'terms' ? 'terms' : 'text',
        case: cs,
        exclude: fields.exclude,
        exclude_devices: extras.xdev,
        trap: $state.snapshot(trapF),
      };
    return {
      ...who,
      from,
      to,
      severities: sev,
      q: q.trim(),
      regex: mode === 'regex',
      syntax: mode === 'terms' ? 'terms' : 'text',
      case: cs,
      app: splitList(fields.app),
      host: splitList(fields.host),
      exclude: fields.exclude,
      facilities: facKeys(extras.fac),
      exclude_devices: extras.xdev,
      exclude_app: extras.xapp,
      exclude_host: extras.xhost,
    };
  }

  // ----- estimate (an upper bound from the index, before building) -----
  let est = $state<ExportEstimate | null>(null);
  let estError = $state('');
  let estBusy = $state(false);
  $effect(() => {
    const key = JSON.stringify({ scope, range, sev, q, mode, cs, fields, extras, xtype, trapF, tab, e: formError });
    void key;
    if (formError || tab !== 'range') {
      est = null;
      return;
    }
    const ctrl = new AbortController();
    const t = setTimeout(async () => {
      estBusy = true;
      try {
        est = await estimateExport(await request(), ctrl.signal);
        estError = '';
      } catch (x) {
        if ((x as Error).name !== 'AbortError') {
          est = null;
          estError = (x as Error).message;
        }
      } finally {
        estBusy = false;
      }
    }, 350);
    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  });

  // ----- the list -----
  let list = $state<ExportInfo[] | null>(null);
  let listError = $state('');
  let building = $state(false);
  let buildError = $state('');
  let now = $state(Date.now());

  async function refresh() {
    try {
      list = await listExports();
      listError = '';
    } catch (x) {
      listError = (x as Error).message;
    }
  }

  // Poll fast while something is queued or building. kick() polls now and re-evaluates the
  // pace, so a new build shows its progress straight away instead of after a slow tick.
  let pollTimer = 0;
  let polling = true;
  async function poll() {
    clearTimeout(pollTimer);
    await refresh();
    now = Date.now();
    if (!polling) return;
    clearTimeout(pollTimer);
    const busy = list?.some((e) => e.state === 'queued' || e.state === 'building');
    pollTimer = window.setTimeout(poll, busy ? 1000 : 5000);
  }
  const kick = () => poll();

  $effect(() => {
    polling = true;
    poll();
    const clock = setInterval(() => (now = Date.now()), 30_000);
    return () => {
      polling = false;
      clearTimeout(pollTimer);
      clearInterval(clock);
    };
  });

  async function build() {
    if (formError || building) return;
    building = true;
    buildError = '';
    try {
      await createExport(await request());
      await kick();
    } catch (x) {
      buildError = (x as Error).message;
    } finally {
      building = false;
    }
  }

  async function remove(e: ExportInfo) {
    try {
      await deleteExport(e.id);
    } catch (x) {
      listError = (x as Error).message;
    }
    await kick();
  }

  // A plain link streams the zip; only mock mode (no server) needs to go through the transport.
  // Downloads always go through a fresh ticket (docs/api.md): a plain link can't carry the
  // session header, and the ticket URL keeps the browser's own download handling for big
  // files. A 401 shows the login (api.ts); a gone or unready export refreshes the list.
  let downloading = $state('');
  let downloadError = $state<Record<string, string>>({});
  async function download(ev: MouseEvent, e: ExportInfo) {
    ev.preventDefault();
    if (downloading) return;
    downloading = e.id;
    downloadError = { ...downloadError, [e.id]: '' };
    try {
      const { url } = await exportTicket(e.id);
      if (downloadsViaTransport()) await transportDownload(url);
      else {
        const a = document.createElement('a');
        a.href = url;
        a.download = '';
        document.body.appendChild(a);
        a.click();
        a.remove();
      }
    } catch (x) {
      const err = x as ApiError;
      if (err.status !== 401) {
        downloadError = {
          ...downloadError,
          [e.id]: err.status === 404 ? 'That export is gone. It may have expired.' : err.status === 409 ? "It isn't ready yet." : err.message,
        };
        kick();
      }
    } finally {
      downloading = '';
    }
  }

  // A group export may list no devices (the server resolves the group when it builds).
  const names = (e: ExportInfo) =>
    e.devices.length
      ? e.devices.slice(0, 3).map(deviceName).join(', ')
      : e.filters?.group
        ? `Group: ${e.filters.group}`
        : e.filters?.ungrouped
          ? 'Ungrouped devices'
          : 'No devices';
  const more = (devs: string[]) => (devs.length > 3 ? `+${devs.length - 3}` : '');
  const expiresIn = (e: ExportInfo) => (e.expires_at ? Date.parse(e.expires_at) - now : DAY);

  /** "Group: HQ · warn, err · “deny” (regex, case)": what the export was asked to include. */
  function filterText(e: ExportInfo): string {
    const f = e.filters;
    if (!f) return '';
    const bits: string[] = [];
    if (isBundle(f)) {
      // A bundle: its devices and types (it has no filters).
      bits.push(f.active_devices ? 'every active device' : f.group ? `group ${f.group}` : f.ungrouped ? 'ungrouped devices' : 'devices chosen');
      bits.push(typesText(f.types));
      return bits.join(' · ');
    }
    const ty = f.types ?? (f.type ? [f.type] : [SYSLOG]);
    if (ty.length !== 1 || ty[0] !== SYSLOG) bits.push(typesText(ty).replace(/^s/, 'S'));
    for (const [k, v] of Object.entries(f.trap ?? {})) if (v.length) bits.push(`${k.replace(/_/g, ' ')}: ${v.join(', ')}`);
    if (e.devices.length && f.group) bits.push(`Group: ${f.group}`);
    if (e.devices.length && f.ungrouped) bits.push('Ungrouped devices');
    if (f.severities?.length) bits.push(f.severities.map((k) => (k === 'unknown' ? 'unknown' : SEVERITIES[k].short)).join(', '));
    if (f.q) {
      const how = [f.regex ? 'regex' : '', f.case ? 'case' : ''].filter(Boolean).join(', ');
      bits.push(`“${f.q}”${how ? ` (${how})` : ''}`);
    }
    if (f.app?.length) bits.push(`program: ${f.app.join(', ')}`);
    if (f.host?.length) bits.push(`host: ${f.host.join(', ')}`);
    if (f.exclude) bits.push(`not “${f.exclude}”`);
    if (f.syntax === 'terms' && (f.q || f.exclude)) bits.push('terms');
    const x = extrasText({ fac: (f.facilities ?? []).map(String), xdev: f.exclude_devices ?? [], xapp: f.exclude_app ?? [], xhost: f.exclude_host ?? [] });
    if (x) bits.push(x);
    return bits.join(' · ');
  }

  const FAC = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
  /** "facility: local7 · not device: edge-fw-02 · not program/tag: kernel" */
  function extrasText(e: Extras): string {
    const bits: string[] = [];
    if (e.fac.length) bits.push(`facility: ${e.fac.map((v) => (v === 'none' || v === 'unknown' ? v : (FAC[Number(v)] ?? v))).join(', ')}`);
    if (e.xdev.length) bits.push(`not device: ${e.xdev.map(deviceName).join(', ')}`);
    if (e.xapp.length) bits.push(`not program/tag: ${e.xapp.join(', ')}`);
    if (e.xhost.length) bits.push(`not host: ${e.xhost.join(', ')}`);
    return bits.join(' · ');
  }
  /** "trap oid: linkDown · status: auth_failed · not device: edge-fw-02": the trap filters in words. */
  function trapText(f: TypeFilters, xdev: string[]): string {
    const bits = Object.entries(f).filter(([, v]) => v.length).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v.join(', ')}`);
    if (xdev.length) bits.push(`not device: ${xdev.map(deviceName).join(', ')}`);
    return bits.join(' · ');
  }
  const STATE: Record<string, string> = { queued: 'Queued', building: 'Building', ready: 'Ready', failed: 'Failed', expired: 'Expired' };
</script>

<div class="grid gap-4 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
  <div class="space-y-4">
    <section class="card space-y-4" aria-labelledby="ex-title">
      <div class="flex flex-wrap items-start gap-3">
        <div class="min-w-0 grow">
          <h1 id="ex-title" class="m-0 text-xl font-bold tracking-tight">Export logs</h1>
          <p class="mt-1 mb-0 text-[13.5px] text-muted">
            {tab === 'around'
              ? 'An incident bundle: everything every device stored around a moment, to send to someone else.'
              : fromSearch
                ? 'Filled in from Events. Check it, then build.'
                : 'Build a zip of the raw logs to send to someone else.'}
          </p>
        </div>
        <div class="seg" role="tablist" aria-label="What to export">
          <button type="button" role="tab" aria-selected={tab === 'range'} onclick={() => (tab = 'range')}>Time range</button>
          <button type="button" role="tab" aria-selected={tab === 'around'} onclick={() => (tab = 'around')}>Around a time</button>
        </div>
      </div>

      {#if tab === 'around'}
        <div class="row top" style:--blab="150px">
          <div class="min-w-0 grow"><BundleWindow bind:value={bform} idp="ex-bw" /></div>
        </div>
        <div class="row">
          <span class="lbl">Devices</span>
          <DevicePicker bind:value={bform.scope} allLabel="Every device active in the window" />
          {#if bform.scope.mode === 'all'}<span class="text-[13px] text-muted">The ones that stored anything in the window; hidden devices only when chosen.</span>{/if}
        </div>
        <div class="row">
          <span class="lbl">Types</span>
          <BundleTypes bind:value={bform.types} types={schemas.length ? schemas : [{ type: SYSLOG, label: 'Syslog', default: true, fields: [] }]} />
        </div>
        <BundleBuild form={bform} formError={bError}>
          <button type="button" class="ghost-btn px-4 py-2" onclick={preview} disabled={!!bError} title="See the window in Events: the histogram, the fields and each device's counts, then build from there">
            Preview in Events
          </button>
        </BundleBuild>
      {:else}

      <div class="row">
        <span class="lbl">Devices</span>
        <DevicePicker bind:value={scope} />
        {#if count !== null}<span class="text-[13px] text-muted">{num(count)} device{count === 1 ? '' : 's'}</span>{/if}
      </div>
      <div class="row top">
        <span class="lbl">Time range</span>
        <div class="min-w-0 grow"><TimeRange bind:value={range} /></div>
      </div>
      {#if hasTraps || xtype !== 'syslog'}
        <div class="row">
          <span class="lbl">Data</span>
          <div class="seg" role="radiogroup" aria-label="Data types">
            <button type="button" role="radio" aria-checked={xtype === 'syslog'} onclick={() => (xtype = 'syslog')}>Syslog</button>
            <button type="button" role="radio" aria-checked={xtype === 'trap'} onclick={() => (xtype = 'trap')}>SNMP traps</button>
            <button type="button" role="radio" aria-checked={xtype === 'both'} onclick={() => (xtype = 'both')}>Both</button>
          </div>
        </div>
      {/if}
      {#if xtype === 'both'}
        <p class="m-0 text-[13.5px] text-muted">
          Both types: every line and trap in the range, in <span class="font-mono">logs/</span> and <span class="font-mono">traps/</span>. Filters apply to one data type, so pick one to filter.
        </p>
      {:else}
      {#if xtype === 'syslog'}
      <div class="row">
        <span class="lbl">Severities</span>
        <div class="sevbar"><SeverityChips bind:value={sev} label="Export severities" /></div>
      </div>
      {/if}
      <div class="row">
        <label class="lbl" for="exq">Only lines matching</label>
        <input
          id="exq"
          class="field w-auto min-w-0 grow basis-40 font-mono"
          bind:value={q}
          placeholder={mode === 'regex' ? 'Regular expression (RE2)' : mode === 'terms' ? 'Optional terms, e.g. deny NOT 10.0.0.1' : 'Optional text'}
          spellcheck="false"
        />
        <ModeSwitch bind:value={mode} />
        <button type="button" class="toggle" aria-pressed={cs} onclick={() => (cs = !cs)} title="Match upper and lower case exactly">Aa Case</button>
      </div>
      {#if xtype === 'syslog'}
      <div class="row">
        <label class="lbl" for="exapp">Program/tag</label>
        <input
          id="exapp"
          class="field w-auto min-w-0 grow basis-40 font-mono"
          bind:value={fields.app}
          placeholder="Optional, e.g. sshd, %FW-6-*"
          spellcheck="false"
        />
      </div>
      <div class="row">
        <label class="lbl" for="exhost">Host</label>
        <input id="exhost" class="field w-auto min-w-0 grow basis-40 font-mono" bind:value={fields.host} placeholder="Optional, e.g. web-01" spellcheck="false" />
      </div>
      {/if}
      <div class="row">
        <label class="lbl" for="exex">Exclude</label>
        <input
          id="exex"
          class="field w-auto min-w-0 grow basis-40 font-mono"
          bind:value={fields.exclude}
          placeholder={mode === 'regex' ? 'Optional regular expression to leave out' : mode === 'terms' ? 'Optional terms to leave out' : 'Optional text to leave out'}
          spellcheck="false"
        />
      </div>

      {#if xtype === 'syslog' && hasExtras(extras)}
        <div class="row">
          <span class="lbl">Also</span>
          <span class="min-w-0 grow text-[13.5px]">{extrasText(extras)}</span>
          <button type="button" class="ghost-btn" onclick={() => (extras = noExtras())} title="Drop these filters from the export">Clear</button>
        </div>
      {/if}
      {#if xtype === 'trap' && (Object.keys(trapF).length || extras.xdev.length)}
        <div class="row">
          <span class="lbl">Also</span>
          <span class="min-w-0 grow font-mono text-[13px]">{trapText(trapF, extras.xdev)}</span>
          <button type="button" class="ghost-btn" onclick={() => ((trapF = {}), (extras = noExtras()))} title="Drop these filters from the export">Clear</button>
        </div>
      {/if}
      {/if}

      <div class="estimate" aria-live="polite">
        {#if formError}
          <span class="text-bad-fg font-medium">{formError}</span>
        {:else if estError}
          <span class="text-bad-fg font-medium">{estError}</span>
        {:else if est}
          <span>Up to <b>{num(est.lines)}</b> lines from <b>{num(est.files)}</b> file{est.files === 1 ? '' : 's'}, about <b>{bytes(est.bytes)}</b> before compression.</span>
          {#if estBusy}<span class="text-muted"> Updating…</span>{/if}
        {:else}
          <span class="text-muted">Estimating…</span>
        {/if}
      </div>

      <div class="flex flex-wrap items-center gap-3">
        <button type="button" class="pill-btn px-5 py-2.5" onclick={build} disabled={!!formError || building}>
          <Icon name="export" size={15} />{building ? 'Starting…' : 'Build the zip'}
        </button>
        {#if buildError}<span class="text-[13.5px] font-medium text-bad-fg" role="alert">{buildError}</span>{/if}
        <span class="text-[13px] text-muted">One export builds at a time; others wait in the queue.</span>
      </div>
      {/if}
    </section>

    {#if tab === 'around'}
    <section class="card">
      <h2 class="m-0 mb-2 text-[16px] font-bold">What's in the bundle</h2>
      <ul class="m-0 list-disc space-y-1.5 pl-5 text-[14px] leading-relaxed">
        <li><b>Everything in the window</b>, from every device you picked: syslog in <span class="font-mono">logs/</span>, SNMP traps in <span class="font-mono">traps/</span>, one file per device per day. No filters: filtering is what a time-range export is for.</li>
        <li><b>A summary per device</b> in <span class="font-mono">README.txt</span>: how many messages of each severity, the traps by name, reboots, gaps and losses.</li>
        <li><b>A manifest</b> with the moment, the window, the devices and a SHA-256 checksum for every file, and <b>Woodshed's own events</b> for the window.</li>
        <li>A window that would end after now ends now. Preview it in Events to see the histogram, the fields and each device's counts first.</li>
      </ul>
    </section>
    {:else}
    <section class="card">
      <h2 class="m-0 mb-2 text-[16px] font-bold">What's in the zip</h2>
      <ul class="m-0 list-disc space-y-1.5 pl-5 text-[14px] leading-relaxed">
        <li><b>The logs</b>, one plain-text file per device per day, exactly as received, so anyone can open them.</li>
        <li><b>A manifest</b> with the devices, range and filters, and a line count and SHA-256 checksum for every file, so the recipient can tell nothing was changed or lost.</li>
        <li><b>A gaps report</b>: times when Woodshed wasn't running or a listener was down. "No logs at 14:05" then means something definite.</li>
        <li><b>Woodshed's own events</b> for the range (restarts, rotations, deletions, drops), so "the device sent nothing" can be told apart from "Woodshed wasn't listening".</li>
      </ul>
    </section>
    {/if}
  </div>

  <section class="card self-start" aria-labelledby="ex-list">
    <h2 id="ex-list" class="m-0 mb-1 text-[16px] font-bold">Recent exports</h2>
    <p class="mt-0 mb-3 text-[13px] text-muted">Each zip is kept for 24 hours after it's ready.</p>
    {#if listError}<p class="text-[13.5px] text-bad-fg" role="alert">{listError}</p>{/if}
    {#if list === null}
      <p class="text-muted">Loading…</p>
    {:else if !list.length}
      <p class="text-muted">No exports yet.</p>
    {:else}
      <ul class="m-0 list-none space-y-2.5 p-0">
        {#each list as e (e.id)}
          <li class="ex" data-id={e.id} data-state={e.state}>
            <div class="flex items-start gap-3">
              <div class="min-w-0 grow">
                <div class="flex min-w-0 items-center gap-2">
                  <span class="shrink-0 badge {e.state}">{STATE[e.state] ?? e.state}</span>
                  {#if isBundle(e.filters)}
                    <span class="shrink-0 badge kind" title="An incident bundle: everything around a moment">Bundle</span>
                    <b class="min-w-0 text-[14px] leading-snug" title={bundleTitle(e.filters.at ?? e.from, e.filters.before ?? '', e.filters.after ?? '', prefs.utc, now)}
                      >{bundleTitle(e.filters.at ?? e.from, e.filters.before ?? '', e.filters.after ?? '', prefs.utc, now)}</b
                    >
                  {:else}
                    <b class="min-w-0 truncate text-[14px]" title={e.devices.map(deviceName).join(', ')}>{names(e)}</b>
                    {#if more(e.devices)}<span class="shrink-0 text-[13px] text-muted">{more(e.devices)}</span>{/if}
                  {/if}
                </div>
                {#if isBundle(e.filters)}
                  <div class="mt-1 truncate text-[13px]" title={e.devices.map(deviceName).join(', ')}>
                    {e.devices.length ? `${num(e.devices.length)} device${e.devices.length === 1 ? '' : 's'}: ${names(e)}${more(e.devices) ? ` ${more(e.devices)}` : ''}` : names(e)}
                  </div>
                {/if}
                {#if filterText(e)}<div class="mt-1 font-mono text-[12px]" class:truncate={!isBundle(e.filters)} title={filterText(e)}>{filterText(e)}</div>{/if}
                <div class="mt-1 text-[12.5px] text-muted">
                  {stamp(e.from, prefs.utc).slice(0, 11)} → {stamp(e.to, prefs.utc).slice(0, 11)}{prefs.utc ? ' UTC' : ''} · created {ago(e.created, now)}
                </div>
              </div>
              <div class="flex shrink-0 items-center gap-2">
                {#if e.state === 'ready'}
                  <a class="pill-btn no-underline" href={exportDownloadUrl(e.id)} download onclick={(ev) => download(ev, e)} aria-busy={downloading === e.id}>
                    <Icon name="download" size={14} />{downloading === e.id ? 'Starting…' : 'Download'}
                  </a>
                {/if}
                <button type="button" class="ghost-btn" onclick={() => remove(e)}>
                  {e.state === 'queued' || e.state === 'building' ? 'Cancel' : 'Delete'}
                </button>
              </div>
            </div>
            {#if e.state === 'building'}
              <div class="bar mt-2" role="progressbar" aria-label="Export progress" aria-valuenow={Math.round(e.progress * 100)} aria-valuemin={0} aria-valuemax={100}>
                <i style:width="{Math.max(2, e.progress * 100)}%"></i>
              </div>
              <div class="mt-1 text-[12.5px] text-muted">{Math.round(e.progress * 100)} % · {num(e.lines)} lines so far</div>
            {:else if e.state === 'queued'}
              <div class="mt-1 text-[12.5px] text-muted">Waiting for the export ahead of it.</div>
            {:else if e.state === 'ready'}
              <div class="mt-1 text-[12.5px] text-muted">
                {num(e.lines)} lines · {bytes(e.size_bytes)} · expires in {remaining(expiresIn(e))}
              </div>
            {/if}
            {#if downloadError[e.id]}
              <div class="mt-1 text-[12.5px] font-medium text-bad-fg" role="alert">{downloadError[e.id]}</div>
            {/if}
            {#if e.state === 'failed'}
              <div class="mt-1 text-[12.5px] font-medium text-bad-fg">{e.error || 'The build failed.'}</div>
            {:else if e.state === 'expired'}
              <div class="mt-1 text-[12.5px] text-muted">Deleted after 24 hours. Build it again if you still need it.</div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </section>
</div>

<style>
  .row {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 14px;
  }
  .row.top {
    align-items: flex-start;
  }
  .row.top > .lbl {
    padding-top: 8px;
  }
  .lbl {
    width: 150px;
    font-size: 13.5px;
    font-weight: 600;
  }
  .sevbar {
    display: inline-flex;
    padding: 6px 10px;
    border-radius: 14px;
    background: var(--log-bar);
    border: 1px solid var(--log-border);
  }
  .toggle {
    padding: 7px 11px;
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
  .estimate {
    padding: 10px 14px;
    border-radius: 14px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
    font-size: 14px;
  }
  .ex {
    padding: 12px 14px;
    border-radius: 16px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
  }
  .badge {
    font-size: 11.5px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid var(--divider);
    background: var(--chip);
  }
  .badge.ready {
    color: var(--ok-fg);
  }
  .badge.building,
  .badge.queued {
    color: var(--link);
  }
  .badge.failed {
    color: var(--bad-fg);
  }
  .badge.expired {
    color: var(--muted);
  }
  .badge.kind {
    color: var(--fg);
    background: var(--glass);
  }
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 3px;
  }
  .seg button {
    height: 28px;
    border: 0;
    background: transparent;
    color: var(--fg);
    padding: 0 12px;
    border-radius: 999px;
    font-size: 13px;
    cursor: pointer;
    white-space: nowrap;
  }
  .seg button[aria-checked='true'],
  .seg button[aria-selected='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
  .bar {
    height: 8px;
    border-radius: 99px;
    background: var(--divider);
    overflow: hidden;
  }
  .bar i {
    display: block;
    height: 100%;
    border-radius: 99px;
    background: var(--spark);
    transition: width 0.25s;
  }
</style>

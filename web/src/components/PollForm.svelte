<script lang="ts">
  // Add or change polling of one device (SPEC §12.5): address and port, the device its data goes
  // to, version, community or v3 user, interval, presets, interfaces and custom OIDs. Test poll
  // runs the configured poll once without saving and shows each step (§12.7). The community is
  // write-only: an existing one shows "set", and leaving the field empty keeps it.
  import { onMount, tick, untrack } from 'svelte';
  import {
    ApiError,
    createPollTarget,
    deletePollTarget,
    getPollTarget,
    getSnmpUsers,
    isConflict,
    testPoll,
    updatePollTarget,
    type SnmpUser,
  } from '../lib/api';
  import {
    DEFAULT_ROWS,
    exitLabel,
    keepsCommunity,
    MAX_CUSTOM,
    newPollForm,
    pollTargetBody,
    PRESETS,
    stepLabel,
    targetErrors,
    type PollFormState,
    type PollSettings,
    type PollTarget,
    type PollTargetInput,
    type PollTestResult,
    type PollVersion,
  } from '../lib/poll';
  import Icon from './Icon.svelte';

  let {
    target = null,
    address = '',
    device = '',
    defaults = null,
    onclose,
    onsaved,
  }: {
    /** The target to change; null adds one. */
    target?: PollTarget | null;
    /** Prefilled for "Add polling" on a device. */
    address?: string;
    device?: string;
    defaults?: PollSettings | null;
    onclose: () => void;
    onsaved: (t: PollTarget | null) => void;
  } = $props();

  // The form starts from the props once (App.svelte keys it on each opening).
  const init = untrack(() => ({ d: defaults, t0: target, address, device }));
  const d = init.d;
  const t0 = init.t0;
  let f = $state<PollFormState>(newPollForm(t0, d, init.address, init.device));
  let users = $state<SnmpUser[] | null>(null);
  let etag = '';
  let errors = $state<Record<string, string>>({});
  let formError = $state('');
  let busy = $state(false);
  let testing = $state(false);
  let test = $state<PollTestResult | null>(null);
  let testNote = $state('');
  let confirmDelete = $state(false);
  let first: HTMLInputElement | undefined = $state();
  let testBox: HTMLElement | undefined = $state();

  onMount(() => {
    getSnmpUsers().then(
      (u) => (users = u),
      () => (users = []),
    );
    if (t0)
      getPollTarget(t0.id).then(
        (r) => (etag = r.etag),
        () => (etag = ''),
      );
    tick().then(() => first?.focus());
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && onclose();
    addEventListener('keydown', esc);
    return () => removeEventListener('keydown', esc);
  });

  const body = (): PollTargetInput => pollTargetBody(f, t0);
  const communityStored = $derived(keepsCommunity(f, t0));

  function check(b: PollTargetInput): boolean {
    errors = targetErrors(b, { creating: !t0, communitySet: communityStored });
    formError = Object.keys(errors).length ? 'Some fields need fixing.' : '';
    return !formError;
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    const b = body();
    if (!check(b)) return;
    busy = true;
    try {
      if (t0) onsaved((await updatePollTarget(t0.id, b, etag)).target);
      else onsaved(await createPollTarget(b));
    } catch (x) {
      if (isConflict(x)) formError = 'This target changed since you opened it (in another tab or by a script). Close and open it again to see the change.';
      else if (x instanceof ApiError && Object.keys(x.fields).length) {
        errors = x.fields;
        formError = x.message || 'Some fields need fixing.';
      } else formError = (x as Error).message;
    } finally {
      busy = false;
    }
  }

  async function remove() {
    if (!t0) return;
    busy = true;
    try {
      await deletePollTarget(t0.id);
      onsaved(null);
    } catch (x) {
      formError = (x as Error).message;
    } finally {
      busy = false;
    }
  }

  async function runTest() {
    const b = body();
    testNote = '';
    test = null;
    // A stored community never comes back, so an edit that keeps it is tested as saved.
    const useSaved = !!t0 && f.version !== '3' && f.community === '' && communityStored;
    if (!useSaved && !check(b)) return;
    errors = {};
    formError = '';
    testing = true;
    try {
      test = await testPoll(useSaved ? { id: t0!.id } : b);
      if (useSaved) testNote = 'Tested the saved settings with the stored community. Enter the community again to test your changes before saving.';
    } catch (x) {
      if (x instanceof ApiError && x.status === 429) testNote = `Too many test polls (10 a minute at most). Try again in ${x.retryAfter || 20} s.`;
      else if (x instanceof ApiError && Object.keys(x.fields).length) errors = x.fields;
      else testNote = (x as Error).message;
    } finally {
      testing = false;
      await tick();
      testBox?.scrollIntoView({ block: 'nearest' });
    }
  }

  const err = (k: string) => errors[k] ?? '';
  function addCustom() {
    if (f.custom.length < MAX_CUSTOM) f.custom = [...f.custom, { oid: '', kind: 'scalar', label: '', max_rows: DEFAULT_ROWS }];
  }
  const INTERVALS = [30, 60, 120, 300, 600];
  const ivText = (s: number) => (s >= 60 ? `${s / 60} min` : `${s} s`);
</script>

<div class="scrim" role="presentation" onclick={onclose}></div>
<div class="dialog glass" role="dialog" aria-modal="true" aria-labelledby="pf-title">
  <form onsubmit={save} novalidate>
    <div class="flex items-start justify-between gap-3">
      <h2 class="m-0 text-[18px] font-bold" id="pf-title">{t0 ? `Polling ${t0.address}` : address ? `Add polling for ${address}` : 'Add polling by address'}</h2>
      <button type="button" class="x" aria-label="Close" onclick={onclose}><Icon name="x" size={16} /></button>
    </div>
    <p class="hint">
      Woodshed sends SNMP Get, GetNext and GetBulk requests to this address only, at the interval below; it never sets anything. Saving starts
      polling within one interval.
    </p>

    <div class="row">
      <label class="lbl grow">
        <span>Address</span>
        <input bind:this={first} class="field font-mono" bind:value={f.address} placeholder="10.1.0.1" spellcheck="false" aria-invalid={!!err('address')} aria-describedby="pe-address" />
        {#if err('address')}<span class="ferr" id="pe-address">{err('address')}</span>{/if}
      </label>
      <label class="lbl w-28">
        <span>UDP port</span>
        <input class="field" type="number" min="1" max="65535" bind:value={f.port} aria-invalid={!!err('port')} aria-describedby="pe-port" />
        {#if err('port')}<span class="ferr" id="pe-port">{err('port')}</span>{/if}
      </label>
    </div>
    <label class="check mt-2">
      <input type="checkbox" bind:checked={f.otherDevice} />
      <span>Store under another device <span class="hint m-0">(for a device that sends syslog from another address)</span></span>
    </label>
    {#if f.otherDevice}
      <label class="lbl mt-1">
        <span>Device (its syslog address)</span>
        <input class="field font-mono" bind:value={f.device} placeholder={f.address || '10.1.0.1'} spellcheck="false" aria-invalid={!!err('device_id')} aria-describedby="pe-dev" />
        {#if err('device_id')}<span class="ferr" id="pe-dev">{err('device_id')}</span>{/if}
      </label>
    {/if}

    <fieldset class="mt-3">
      <legend class="lbl-t">Version</legend>
      <div class="seg" role="radiogroup" aria-label="SNMP version">
        {#each ['1', '2c', '3'] as v (v)}
          <button type="button" role="radio" aria-checked={f.version === v} onclick={() => (f.version = v as PollVersion)}>v{v}</button>
        {/each}
      </div>
    </fieldset>
    {#if f.version === '3'}
      <label class="lbl mt-2">
        <span>v3 user</span>
        <select class="field" bind:value={f.v3User} aria-invalid={!!err('v3_user')} aria-describedby="pe-user">
          <option value="">Choose a user…</option>
          {#each users ?? [] as u (u.name)}<option value={u.name}>{u.name} ({u.level}{u.auth !== 'none' ? `, ${u.auth}` : ''}{u.priv !== 'none' ? `/${u.priv}` : ''})</option>{/each}
        </select>
        <span class="hint m-0">The same users as the trap receiver. Add or change them in <a class="text-link underline" href="#/settings?section=snmp-users">Settings → SNMP traps</a>.</span>
        {#if err('v3_user')}<span class="ferr" id="pe-user">{err('v3_user')}</span>{/if}
      </label>
    {:else}
      <label class="lbl mt-2">
        <span>Community {#if communityStored}<span class="set">set</span>{/if}</span>
        <input class="field" type="password" autocomplete="off" bind:value={f.community} placeholder={communityStored ? 'Leave empty to keep the stored one' : ''} aria-invalid={!!err('community')} aria-describedby="pe-comm" />
        <span class="hint m-0">Kept in the credentials store and never shown again; poll lines name it only by a hash prefix.</span>
        {#if err('community')}<span class="ferr" id="pe-comm">{err('community')}</span>{/if}
      </label>
    {/if}

    <div class="row mt-3">
      <label class="lbl">
        <span>Every</span>
        <select class="field" bind:value={f.interval} aria-invalid={!!err('interval_s')} aria-describedby="pe-iv">
          {#each [...new Set([...INTERVALS, Number(f.interval)])].sort((a, b) => a - b) as s (s)}<option value={s}>{ivText(s)}</option>{/each}
        </select>
        {#if err('interval_s')}<span class="ferr" id="pe-iv">{err('interval_s')}</span>{/if}
      </label>
      <label class="lbl w-28">
        <span>Timeout (ms)</span>
        <input class="field" type="number" min="200" max="10000" step="100" bind:value={f.timeoutMs} aria-invalid={!!err('timeout_ms')} />
        {#if err('timeout_ms')}<span class="ferr">{err('timeout_ms')}</span>{/if}
      </label>
      <label class="lbl w-24">
        <span>Retries</span>
        <input class="field" type="number" min="0" max="5" bind:value={f.retries} aria-invalid={!!err('retries')} />
        {#if err('retries')}<span class="ferr">{err('retries')}</span>{/if}
      </label>
    </div>

    <fieldset class="mt-3">
      <legend class="lbl-t">What to poll</legend>
      {#each PRESETS as p (p.key)}
        <label class="check">
          <input type="checkbox" value={p.key} bind:group={f.presets} />
          <span>{p.label} <span class="hint m-0">{p.hint}</span></span>
        </label>
      {/each}
      {#if err('presets')}<span class="ferr">{err('presets')}</span>{/if}
    </fieldset>

    {#if f.presets.includes('interfaces')}
      <fieldset class="mt-3">
        <legend class="lbl-t">Interfaces</legend>
        <label class="check"><input type="radio" value="all" bind:group={f.ifMode} /> <span>All, up to the cap</span></label>
        {#if f.ifMode === 'all'}
          <div class="row ml-6">
            <label class="lbl w-28">
              <span>Cap</span>
              <input class="field" type="number" min="1" max="1024" bind:value={f.maxIf} aria-invalid={!!err('max_interfaces')} />
              {#if err('max_interfaces')}<span class="ferr">{err('max_interfaces')}</span>{/if}
            </label>
            <label class="lbl grow">
              <span>Pinned (always within the cap)</span>
              <input class="field font-mono" bind:value={f.pinned} placeholder="eth1, gi1/0/48, 7" spellcheck="false" />
              <span class="hint m-0">Over the cap, pinned interfaces come first, then those that are up, fastest first.</span>
            </label>
          </div>
        {/if}
        <label class="check"><input type="radio" value="list" bind:group={f.ifMode} /> <span>Only these</span></label>
        {#if f.ifMode === 'list'}
          <label class="lbl ml-6">
            <span class="sr-only">Interface names or indexes</span>
            <input class="field font-mono" bind:value={f.ifList} placeholder="eth1, eth2, 7 (names or ifIndexes)" spellcheck="false" aria-invalid={!!err('interfaces')} />
            {#if err('interfaces')}<span class="ferr">{err('interfaces')}</span>{/if}
          </label>
        {/if}
      </fieldset>
    {/if}

    <fieldset class="mt-3">
      <legend class="lbl-t">Custom OIDs ({f.custom.length} of {MAX_CUSTOM})</legend>
      {#each f.custom as c, i (i)}
        <div class="crow">
          <input class="field font-mono" bind:value={c.oid} placeholder="1.3.6.1.4.1.32473.1.2.0" aria-label="OID {i + 1}" spellcheck="false" aria-invalid={!!err(`custom[${i}].oid`)} />
          <select class="field" bind:value={c.kind} aria-label="Kind of OID {i + 1}">
            <option value="scalar">Get</option>
            <option value="walk">Walk</option>
          </select>
          <input class="field" bind:value={c.label} placeholder="Label" aria-label="Label of OID {i + 1}" maxlength="64" />
          {#if c.kind === 'walk'}
            <input class="field" type="number" min="1" max="1024" bind:value={c.max_rows} aria-label="Most rows of OID {i + 1}" title="Most rows" aria-invalid={!!err(`custom[${i}].max_rows`)} />
          {:else}<span></span>{/if}
          <button type="button" class="x" aria-label="Remove OID {i + 1}" onclick={() => (f.custom = f.custom.filter((_, k) => k !== i))}><Icon name="x" size={14} /></button>
        </div>
        {#each [`custom[${i}].oid`, `custom[${i}].max_rows`, `custom[${i}].label`] as k (k)}{#if err(k)}<p class="ferr m-0">OID {i + 1}: {err(k)}</p>{/if}{/each}
      {/each}
      {#if err('custom')}<p class="ferr">{err('custom')}</p>{/if}
      <button type="button" class="ghost-btn mt-1" onclick={addCustom} disabled={f.custom.length >= MAX_CUSTOM}><Icon name="plus" size={14} />Add an OID</button>
      <p class="hint m-0 mt-1">A Get reads one value; a walk reads a table column or a small subtree (at most the rows given, 128 by default). Counters become rates.</p>
    </fieldset>

    {#if t0}
      <label class="check mt-3"><input type="checkbox" bind:checked={f.enabled} /> <span>Polling on <span class="hint m-0">(off keeps the settings and the stored data)</span></span></label>
    {/if}

    {#if test || testNote || testing}
      <section class="test" aria-live="polite" aria-label="Test poll" bind:this={testBox}>
        {#if testing}<p class="m-0 text-muted">Polling {f.address}…</p>{/if}
        {#if test}
          <p class="m-0 font-semibold" class:text-ok-fg={test.exit === 'ok'} class:text-bad-fg={test.exit === 'no_answer' || test.exit === 'auth'} class:text-warn-fg={test.exit === 'partial'}>
            Test poll: {exitLabel(test.exit)}
          </p>
          <ol class="steps">
            {#each test.steps as s, i (i)}
              <li class:bad={!s.ok}>
                <span class="mk" aria-label={s.ok ? 'answered' : 'failed'}>{s.ok ? '✓' : '✗'}</span>
                <span><b>{stepLabel(s.step)}</b>: {s.detail}{#if s.rtt_ms !== null}<span class="rtt"> · {s.rtt_ms} ms</span>{/if}</span>
              </li>
            {/each}
          </ol>
        {/if}
        {#if testNote}<p class="m-0 mt-1 text-[13px] text-muted">{testNote}</p>{/if}
      </section>
    {/if}

    {#if formError}<p class="ferr mt-3" role="alert">{formError}</p>{/if}
    <div class="mt-4 flex flex-wrap items-center gap-2">
      {#if t0}
        {#if confirmDelete}
          <span class="text-[13px]">Stop polling? The stored poll data stays until retention deletes it.</span>
          <button type="button" class="ghost-btn danger" onclick={remove} disabled={busy}>Stop polling</button>
          <button type="button" class="ghost-btn" onclick={() => (confirmDelete = false)}>Keep</button>
        {:else}
          <button type="button" class="ghost-btn" onclick={() => (confirmDelete = true)}><Icon name="trash" size={14} />Delete</button>
        {/if}
      {/if}
      <span class="grow"></span>
      <button type="button" class="ghost-btn" onclick={runTest} disabled={testing || busy}><Icon name="flask" size={14} />{testing ? 'Testing…' : 'Test poll'}</button>
      <button type="button" class="ghost-btn" onclick={onclose}>Cancel</button>
      <button type="submit" class="pill-btn" disabled={busy}>{busy ? 'Saving…' : t0 ? 'Save' : 'Start polling'}</button>
    </div>
  </form>
</div>

<style>
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 70;
    background: rgba(10, 12, 16, 0.45);
  }
  .dialog {
    position: fixed;
    z-index: 71;
    left: 50%;
    top: 4vh;
    transform: translateX(-50%);
    width: min(640px, calc(100vw - 32px));
    max-height: 92vh;
    overflow-y: auto;
    padding: 22px;
    border-radius: 22px;
    background: var(--glass-strong);
    box-shadow: var(--shadow);
    -webkit-backdrop-filter: blur(20px);
    backdrop-filter: blur(20px);
  }
  fieldset {
    border: 0;
    margin: 0;
    padding: 0;
  }
  .hint {
    font-size: 13px;
    color: var(--muted);
    margin: 4px 0 12px;
  }
  .lbl {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13.5px;
    font-weight: 500;
  }
  .lbl-t {
    font-size: 13.5px;
    font-weight: 600;
    margin-bottom: 6px;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px 14px;
    align-items: flex-start;
  }
  .row > .grow {
    flex: 1;
    min-width: 200px;
  }
  .check {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 14px;
    margin: 3px 0;
  }
  .ferr {
    font-size: 13px;
    font-weight: 500;
    color: var(--bad-fg);
  }
  .set {
    margin-left: 6px;
    padding: 0 7px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 600;
    border: 1px solid var(--ok);
    color: var(--ok-fg);
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
    padding: 4px 14px;
    border-radius: 999px;
    font-size: 13px;
    cursor: pointer;
  }
  .seg button[aria-checked='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
  .crow {
    display: grid;
    grid-template-columns: minmax(0, 2.2fr) 82px minmax(0, 1.2fr) 74px 28px;
    gap: 6px;
    align-items: center;
    margin-bottom: 6px;
  }
  .crow .field {
    padding: 6px 8px;
    font-size: 13px;
  }
  .x {
    display: inline-grid;
    place-items: center;
    width: 28px;
    height: 28px;
    border-radius: 999px;
    border: 0;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }
  .x:hover {
    background: var(--glass);
    color: var(--fg);
  }
  .test {
    margin-top: 14px;
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid var(--divider);
    background: var(--glass);
    font-size: 13.5px;
  }
  .steps {
    margin: 6px 0 0;
    padding: 0;
    list-style: none;
  }
  .steps li {
    display: flex;
    gap: 8px;
    padding: 2px 0;
  }
  .mk {
    color: var(--ok-fg);
    font-weight: 700;
  }
  .steps li.bad .mk {
    color: var(--bad-fg);
  }
  .rtt {
    color: var(--muted);
  }
  .danger {
    border-color: var(--error-border);
    color: var(--bad-fg);
  }
</style>

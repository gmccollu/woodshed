<script lang="ts">
  // Settings → SNMP traps, the parts that come from the SNMP routes rather than the settings
  // form (SPEC §11.2.5, docs/api.md → SNMP state, SNMP v3 users): the firewall hint, the engine
  // ID, the v3 users (saved at once, each on its own), the MIB folder, the last 24 h and the
  // senders with failures. Passphrases are write-only: they're sent once and only ever shown as
  // "set".
  import {
    ApiError,
    createSnmpUser,
    deleteSnmpUser,
    getSnmp,
    getSnmpFailures,
    getSnmpUsers,
    reloadMibs,
    updateSnmpUser,
    type SnmpAuth,
    type SnmpFailure,
    type SnmpKeyExt,
    type SnmpPriv,
    type SnmpState,
    type SnmpUser,
  } from '../lib/api';
  import { ago, dateTime, num } from '../lib/format';
  import { deviceName, live, refreshStatus } from '../lib/status.svelte';
  import { AUTHS, PRIVS, authLabel, isWeak, levelOf, needsKeyExt, parseEngineIds, privLabel, statusLabel, userErrors } from '../lib/traps';
  import CopyButton from './CopyButton.svelte';
  import Icon from './Icon.svelte';

  /** The saved settings' listeners.snmp.enabled and port; `reload` changes after every save. */
  let { enabled, port, reload = 0 }: { enabled: boolean; port: number; reload?: number } = $props();

  let st = $state<SnmpState | null>(null);
  let loadError = $state('');
  let failures = $state<SnmpFailure[] | null>(null);
  let users = $state<SnmpUser[] | null>(null);

  async function load() {
    try {
      st = await getSnmp();
      loadError = '';
    } catch (e) {
      loadError = (e as Error).message;
    }
    try {
      failures = await getSnmpFailures();
    } catch {
      failures = failures ?? [];
    }
    try {
      users = await getSnmpUsers();
    } catch {
      users = users ?? [];
    }
  }

  $effect(() => {
    void reload;
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  });

  const os = $derived(live.status?.os ?? '');
  const isWindows = $derived(os.startsWith('windows'));
  const isMac = $derived(os.startsWith('darwin'));
  const ufw = $derived(`sudo ufw allow ${port}/udp`);
  const firewalld = $derived(`sudo firewall-cmd --permanent --add-port=${port}/udp && sudo firewall-cmd --reload`);
  const fwText = $derived<Record<string, string>>({
    missing: 'The Windows firewall has no rule for SNMP traps yet, so devices may not get through.',
    disabled: 'The Windows firewall rule "Woodshed SNMP traps" is turned off, so devices may not get through.',
    wrong_port: `The Windows firewall rule for SNMP traps is for a different port, not ${port}.`,
    unknown: `Woodshed can't tell whether the Windows firewall lets devices in on UDP ${port}.`,
  });

  /** engineTime as "3 h 17 min" (seconds since this start). */
  function uptime(s: number): string {
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
  }

  // ---- Reload MIBs ----
  let mibBusy = $state(false);
  let mibDone = $state('');
  let mibError = $state('');
  async function reloadMibFolder() {
    mibBusy = true;
    mibDone = mibError = '';
    try {
      const m = await reloadMibs();
      if (st) st = { ...st, mibs: m };
      mibDone = `Read ${num(m.files)} file${m.files === 1 ? '' : 's'}: ${num(m.names)} names${m.errors.length ? `, ${m.errors.length} file${m.errors.length === 1 ? '' : 's'} skipped` : ''}.`;
      refreshStatus();
    } catch (e) {
      mibError = `Couldn't reload the MIBs: ${(e as Error).message}`;
    } finally {
      mibBusy = false;
    }
  }

  // ---- v3 users: add, edit, delete, each saved at once ----
  interface UserForm {
    /** The name being edited, or null for a new user. */
    orig: string | null;
    name: string;
    auth: SnmpAuth;
    priv: SnmpPriv;
    keyExt: SnmpKeyExt;
    authPass: string;
    privPass: string;
    engineIds: string;
    /** The stored user's protocols and whether a passphrase is set, to tell what can be kept. */
    was: SnmpUser | null;
  }
  let uf = $state<UserForm | null>(null);
  let ufErrors = $state<Record<string, string>>({});
  let ufBusy = $state(false);
  let ufError = $state('');
  let confirmDelete = $state('');
  let usersDone = $state('');

  function newUser() {
    uf = { orig: null, name: '', auth: 'sha-256', priv: 'aes-128', keyExt: 'draft', authPass: '', privPass: '', engineIds: '', was: null };
    ufErrors = {};
    ufError = usersDone = '';
  }

  function editUser(u: SnmpUser) {
    uf = {
      orig: u.name,
      name: u.name,
      auth: u.auth as SnmpAuth,
      priv: u.priv as SnmpPriv,
      keyExt: (u.key_ext as SnmpKeyExt) || 'draft',
      authPass: '',
      privPass: '',
      engineIds: u.engine_ids.join('\n'),
      was: u,
    };
    ufErrors = {};
    ufError = usersDone = '';
  }

  /** An empty passphrase keeps the stored one when the protocol is the same and the stored one is readable here. */
  const keepAuth = $derived(!!uf?.was && uf.was.readable && uf.was.auth_set && uf.was.auth === uf.auth);
  const keepPriv = $derived(!!uf?.was && uf.was.readable && uf.was.priv_set && uf.was.priv === uf.priv);

  async function saveUser(e: SubmitEvent) {
    e.preventDefault();
    if (!uf) return;
    const ids = parseEngineIds(uf.engineIds);
    ufErrors = userErrors({ name: uf.name, auth: uf.auth, priv: uf.priv, auth_pass: uf.authPass, priv_pass: uf.privPass, engine_ids: ids, keepAuth, keepPriv });
    if (Object.keys(ufErrors).length) return;
    const body = {
      name: uf.name,
      auth: uf.auth,
      priv: uf.auth === 'none' ? ('none' as SnmpPriv) : uf.priv,
      key_ext: needsKeyExt(uf.priv) ? uf.keyExt : ('draft' as SnmpKeyExt),
      engine_ids: ids,
      ...(uf.authPass ? { auth_pass: uf.authPass } : {}),
      ...(uf.privPass ? { priv_pass: uf.privPass } : {}),
    };
    ufBusy = true;
    ufError = '';
    try {
      const u = uf.orig === null ? await createSnmpUser(body) : await updateSnmpUser(uf.orig, body);
      usersDone = `${uf.orig === null ? 'Added' : 'Saved'} ${u.name}.`;
      uf = null; // the passphrases leave the page with the form
      users = await getSnmpUsers();
      refreshStatus();
    } catch (x) {
      if (x instanceof ApiError && Object.keys(x.fields).length) ufErrors = x.fields;
      else ufError = (x as Error).message;
    } finally {
      ufBusy = false;
    }
  }

  async function removeUser(name: string) {
    try {
      await deleteSnmpUser(name);
      usersDone = `Deleted ${name}.`;
      confirmDelete = '';
      users = await getSnmpUsers();
      refreshStatus();
    } catch (x) {
      usersDone = '';
      ufError = (x as Error).message;
    }
  }

  const byStatus = $derived(Object.entries(st?.counts_24h.by_status ?? {}).sort((a, b) => b[1] - a[1]));
</script>

{#snippet weak(proto: string, label: string)}
  {label}{#if isWeak(proto)}<span class="weak" title="Weak, but common on older gear: allowed, not refused">weak</span>{/if}
{/snippet}

{#if loadError && !st}
  <p class="hint text-bad-fg" role="alert">Couldn't read the SNMP state: {loadError}</p>
{:else if !st}
  <p class="hint">Loading…</p>
{:else}
  {#if isWindows && enabled && st.firewall.state !== 'ok' && st.firewall.command}
    <div class="fwbox" role="note" data-snmp-firewall>
      <p class="m-0 text-[13.5px]">
        <b>{fwText[st.firewall.state] ?? 'The Windows firewall may block devices.'}</b> Run this once in a Command Prompt or PowerShell opened with
        <b>Run as administrator</b>:
      </p>
      <div class="log-panel mt-2 flex items-start gap-3 rounded-2xl p-3">
        <code class="grow text-[13px] leading-relaxed break-all whitespace-pre-wrap">{st.firewall.command}</code>
        <CopyButton text={st.firewall.command} />
      </div>
    </div>
  {/if}

  <div class="grid2">
    <div class="box" id="snmp-engine">
      <h3 class="bh">Woodshed's engine ID <span class="sub">for v3 informs</span></h3>
      <div class="fp-row">
        <code class="fp">{st.engine.id}</code>
        <CopyButton text={st.engine.id} label="Copy" />
      </div>
      <p class="hint mt-2 mb-0">
        Boots {num(st.engine.boots)} · time {num(st.engine.time)} s ({uptime(st.engine.time)}). Devices that send informs with a fixed receiver engine ID
        need this one. Traps use each device's own engine ID instead.
      </p>
    </div>
    <div class="box" id="snmp-counts">
      <h3 class="bh">Last 24 hours</h3>
      <dl>
        <dt>Received</dt>
        <dd class="tabular-nums">{num(st.counts_24h.received)}</dd>
        <dt>Informs answered</dt>
        <dd class="tabular-nums">{num(st.counts_24h.informs_answered)}</dd>
        <dt>Replies rate-limited</dt>
        <dd class="tabular-nums">{num(st.counts_24h.replies_rate_limited)}</dd>
        {#if st.counts_24h.time_resyncs !== undefined}
          <dt title="v3 devices that rebooted without raising their boots: their clock was relearned from an authenticated trap">Clocks relearned</dt>
          <dd class="tabular-nums">{num(st.counts_24h.time_resyncs)}</dd>
        {/if}
        <dt>By status</dt>
        <dd>
          {#each byStatus as [k, n], i (k)}{i ? ', ' : ''}<span class:bad={k !== 'ok'}>{statusLabel(k)} {num(n)}</span>{:else}none{/each}
        </dd>
      </dl>
      {#if enabled}<a class="text-link text-[13px] underline" href="#/events?type=trap&r=24h">Show the traps in Events</a>{/if}
    </div>
  </div>

  <h3 class="mt-5 mb-1 text-[14px] font-semibold" id="snmp-users">v3 users</h3>
  <p class="hint mt-0">
    Each v3 device sends as a user. Passphrases are kept in the data folder, {isWindows ? 'encrypted with Windows DPAPI' : 'in a file only the service account can read'},
    never shown again and never exported. A user accepts its own security level and above.
  </p>
  {#if usersDone}<p class="done" role="status">{usersDone}</p>{/if}
  {#if users === null}
    <p class="hint">Loading…</p>
  {:else}
    {#if users.length}
      <div class="overflow-auto rounded-xl border border-[var(--divider)]">
        <table class="w-full border-collapse text-[13px]" aria-label="SNMP v3 users">
          <thead>
            <tr><th scope="col">User</th><th scope="col">Level</th><th scope="col">Auth</th><th scope="col">Privacy</th><th scope="col">Passphrases</th><th scope="col">Engines</th><th scope="col"><span class="sr-only">Actions</span></th></tr>
          </thead>
          <tbody>
            {#each users as u (u.name)}
              <tr>
                <td class="font-mono font-semibold">{u.name}</td>
                <td>{u.level}</td>
                <td>{@render weak(u.auth, authLabel(u.auth))}</td>
                <td>{@render weak(u.priv, privLabel(u.priv))}{#if needsKeyExt(u.priv)}{' '}<span class="text-muted">({u.key_ext === 'alt' ? 'alt key extension' : 'draft key extension'})</span>{/if}</td>
                <td>
                  {#if !u.readable}
                    <span class="needs" title="The credentials file can't be decrypted on this machine or account">needs its passphrases again</span>
                  {:else if u.stored === 'localized'}
                    <span title="Only the keys for the listed engines are kept; the passphrases were discarded">set (keys only)</span>
                  {:else}
                    {[u.auth !== 'none' ? (u.auth_set ? 'auth set' : 'auth missing') : '', u.priv !== 'none' ? (u.priv_set ? 'priv set' : 'priv missing') : ''].filter(Boolean).join(', ') || '–'}
                  {/if}
                </td>
                <td class="font-mono text-[12px]">{u.engine_ids.length ? u.engine_ids.join(', ') : 'any'}</td>
                <td class="text-right whitespace-nowrap">
                  {#if confirmDelete === u.name}
                    Delete? <button type="button" class="lnk bad" onclick={() => removeUser(u.name)}>Yes</button>
                    <button type="button" class="lnk" onclick={() => (confirmDelete = '')}>No</button>
                  {:else}
                    <button type="button" class="ghost-btn" onclick={() => editUser(u)} aria-label="Edit {u.name}"><Icon name="edit" size={14} />Edit</button>
                    <button type="button" class="ghost-btn" onclick={() => (confirmDelete = u.name)} aria-label="Delete {u.name}"><Icon name="trash" size={14} /></button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else}
      <p class="hint">No v3 users yet. v1 and v2c traps need none.</p>
    {/if}
    {#if !uf}
      <button type="button" class="ghost-btn mt-2" onclick={newUser}>Add a v3 user…</button>
    {:else}
      <form class="uform" onsubmit={saveUser} aria-label={uf.orig === null ? 'Add a v3 user' : `Edit ${uf.orig}`}>
        <h4 class="m-0 mb-2 text-[14px] font-semibold">{uf.orig === null ? 'Add a v3 user' : `Edit ${uf.orig}`}</h4>
        <div class="ugrid">
          <label class="lbl">
            <span>User name</span>
            <input class="field font-mono" bind:value={uf.name} spellcheck="false" autocomplete="off" aria-invalid={!!ufErrors.name} />
            {#if ufErrors.name}<span class="ferr">{ufErrors.name}</span>{/if}
          </label>
          <label class="lbl">
            <span>Authentication</span>
            <select class="field" bind:value={uf.auth}>
              {#each AUTHS as a (a)}<option value={a}>{authLabel(a)}{isWeak(a) ? ' (weak)' : ''}</option>{/each}
            </select>
            {#if ufErrors.auth}<span class="ferr">{ufErrors.auth}</span>{/if}
          </label>
          <label class="lbl">
            <span>Auth passphrase</span>
            <input
              class="field"
              type="password"
              bind:value={uf.authPass}
              disabled={uf.auth === 'none'}
              autocomplete="new-password"
              placeholder={keepAuth ? 'set (leave empty to keep it)' : '8 to 256 characters'}
              aria-invalid={!!ufErrors.auth_pass}
            />
            {#if ufErrors.auth_pass}<span class="ferr">{ufErrors.auth_pass}</span>{/if}
          </label>
          <label class="lbl">
            <span>Privacy</span>
            <select class="field" bind:value={uf.priv} disabled={uf.auth === 'none'}>
              {#each PRIVS as p (p)}<option value={p}>{privLabel(p)}{isWeak(p) ? ' (weak)' : ''}</option>{/each}
            </select>
            {#if ufErrors.priv}<span class="ferr">{ufErrors.priv}</span>{/if}
          </label>
          <label class="lbl">
            <span>Privacy passphrase</span>
            <input
              class="field"
              type="password"
              bind:value={uf.privPass}
              disabled={uf.auth === 'none' || uf.priv === 'none'}
              autocomplete="new-password"
              placeholder={keepPriv ? 'set (leave empty to keep it)' : '8 to 256 characters'}
              aria-invalid={!!ufErrors.priv_pass}
            />
            {#if ufErrors.priv_pass}<span class="ferr">{ufErrors.priv_pass}</span>{/if}
          </label>
          {#if needsKeyExt(uf.priv) && uf.auth !== 'none'}
            <label class="lbl">
              <span>AES key extension</span>
              <select class="field" bind:value={uf.keyExt}>
                <option value="draft">Draft (the usual one)</option>
                <option value="alt">Alternative (some devices)</option>
              </select>
              <span class="hint m-0">Two incompatible ways of making an AES-192/256 key are in use; if traps show "couldn't decrypt", try the other.</span>
            </label>
          {/if}
        </div>
        <label class="lbl mt-3">
          <span>Sender engine IDs <span class="font-normal text-muted">(optional)</span></span>
          <textarea class="field min-h-[56px] font-mono" bind:value={uf.engineIds} spellcheck="false" placeholder="One hex engine ID per line; empty accepts any engine" aria-invalid={Object.keys(ufErrors).some((k) => k.startsWith('engine_ids'))}></textarea>
          {#each Object.entries(ufErrors).filter(([k]) => k.startsWith('engine_ids')) as [k, m] (k)}<span class="ferr">{k.replace(/^engine_ids\[(\d+)\]$/, (_, i) => `Engine ${Number(i) + 1}`)}: {m}</span>{/each}
          <span class="hint m-0">With engine IDs, only the keys for those engines are kept and the passphrases are discarded, so a leak can't reveal a passphrase used elsewhere.</span>
        </label>
        <p class="hint mt-2 mb-0">Level: <b>{levelOf(uf.auth, uf.auth === 'none' ? 'none' : uf.priv)}</b>. Passphrases are sent once over this connection and never shown again.</p>
        {#if ufError}<p class="ferr" role="alert">{ufError}</p>{/if}
        <div class="mt-3 flex gap-2">
          <button type="submit" class="pill-btn" disabled={ufBusy}>{ufBusy ? 'Saving…' : uf.orig === null ? 'Add user' : 'Save user'}</button>
          <button type="button" class="ghost-btn" onclick={() => (uf = null)} disabled={ufBusy}>Cancel</button>
        </div>
      </form>
    {/if}
  {/if}

  <h3 class="mt-5 mb-1 text-[14px] font-semibold" id="snmp-mibs">MIB folder</h3>
  <p class="hint mt-0">
    MIB files (<code>*.mib</code>, <code>*.my</code>, <code>*.txt</code>) give OIDs their names. Woodshed reads only names, notifications and integer
    values from them, at start and when you press Reload MIBs. Stored traps keep the names known when they arrived; Events names every OID from the MIBs
    loaded now.
  </p>
  <div class="box">
    <dl>
      <dt>Folder</dt>
      <dd class="font-mono break-all">{st.mibs.dir}</dd>
      <dt>Loaded</dt>
      <dd>{num(st.mibs.files)} file{st.mibs.files === 1 ? '' : 's'}, {num(st.mibs.names)} names (with the built-in ones){#if st.mibs.loaded_at}, <span title={dateTime(st.mibs.loaded_at)}>{ago(st.mibs.loaded_at, live.now)}</span>{/if}</dd>
    </dl>
    {#if st.mibs.errors.length}
      <p class="m-0 mt-2 text-[13.5px] font-semibold text-bad-fg">Skipped (they didn't parse; the rest loaded):</p>
      <ul class="errs">
        {#each st.mibs.errors as m (m.file + m.line)}<li><code>{m.file}:{m.line}</code> {m.message}</li>{/each}
      </ul>
    {/if}
    {#if st.mibs.warnings?.length}
      <details class="mt-2">
        <summary class="text-[13px]">{st.mibs.warnings.length} warning{st.mibs.warnings.length === 1 ? '' : 's'}</summary>
        <ul class="errs">
          {#each st.mibs.warnings as m (m.file + m.line)}<li><code>{m.file}:{m.line}</code> {m.message}</li>{/each}
        </ul>
      </details>
    {/if}
    <div class="mt-3 flex flex-wrap items-center gap-3">
      <button type="button" class="ghost-btn" onclick={reloadMibFolder} disabled={mibBusy}><Icon name="retry" size={15} />{mibBusy ? 'Reloading…' : 'Reload MIBs'}</button>
      {#if mibDone}<span class="hint m-0" role="status">{mibDone}</span>{/if}
      {#if mibError}<span class="ferr" role="alert">{mibError}</span>{/if}
    </div>
  </div>

  {#if !isWindows}
    <details class="trouble">
      <summary>If traps don't arrive</summary>
      <ul>
        <li>Point the device at UDP port {port} of this machine, with the community or v3 user configured here.</li>
        <li>Port 162 is often taken by the OS's own trap service (snmptrapd); the listener banner names the program holding it.</li>
        <li>v3 traps that fail show in the list below with the reason: an unknown user, a wrong passphrase or an engine ID mismatch.</li>
      </ul>
      {#if isMac}
        <p class="hint mb-2">The macOS firewall allows or blocks programs, not ports: if Woodshed already receives syslog, traps get through too.</p>
      {:else}
        <p class="hint mb-2">
          Host firewall: open UDP port {port}. <code>sudo woodshed snmp on</code> does this for you when ufw or firewalld is active. Otherwise, with ufw:
        </p>
        <div class="cmd log-panel"><code>{ufw}</code><CopyButton text={ufw} /></div>
        <p class="hint mt-2 mb-2">Or with firewalld:</p>
        <div class="cmd log-panel"><code>{firewalld}</code><CopyButton text={firewalld} /></div>
      {/if}
    </details>
  {/if}

  <h3 class="mt-5 mb-1 text-[14px] font-semibold" id="snmp-failures">Senders with failures, last 24 h</h3>
  <p class="hint mt-0">v3 traps that failed, and packets that didn't decode. They're stored too, with their status, so you can find them in Events.</p>
  {#if failures === null}
    <p class="hint">Loading…</p>
  {:else if !failures.length}
    <p class="hint">None.</p>
  {:else}
    <div class="max-h-80 overflow-auto rounded-xl border border-[var(--divider)]">
      <table class="w-full border-collapse text-[13px]" aria-label="Senders with SNMP failures">
        <thead>
          <tr>
            <th scope="col">Sender</th>
            <th scope="col" class="text-right">Failures</th>
            <th scope="col">Last seen</th>
            <th scope="col">Status</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {#each failures as f (f.ip)}
            <tr>
              <td class="whitespace-nowrap">
                <span class="font-mono">{f.ip}</span>
                {#if f.device_id}
                  <a class="text-link ml-1 underline" href="#/events?type=trap&dev={encodeURIComponent(f.device_id)}&status={encodeURIComponent(f.status)}&r=24h" title="Show these traps in Events">
                    {deviceName(f.device_id) !== f.device_id ? deviceName(f.device_id) : 'traps'}
                  </a>
                {/if}
              </td>
              <td class="text-right tabular-nums">{num(f.count_24h)}</td>
              <td class="whitespace-nowrap" title={dateTime(f.last_seen)}>{ago(f.last_seen, live.now)}</td>
              <td>{statusLabel(f.status)}{#if f.time_resyncs_24h}{' '}<span class="text-muted">· clock relearned {num(f.time_resyncs_24h)}×</span>{/if}</td>
              <td class="detail font-mono text-[12px] text-muted">{f.detail}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .hint {
    font-size: 13px;
    color: var(--muted);
    margin-bottom: 10px;
  }
  .grid2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
  }
  @media (max-width: 900px) {
    .grid2 {
      grid-template-columns: 1fr;
    }
  }
  .box {
    padding: 12px 14px;
    border-radius: 16px;
    border: 1px solid var(--input-border);
    min-width: 0;
  }
  .bh {
    margin: 0 0 6px;
    font-size: 14.5px;
    font-weight: 700;
  }
  .bh .sub {
    font-weight: 400;
    font-size: 12.5px;
    color: var(--muted);
    margin-left: 6px;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 3px 12px;
    margin: 0 0 6px;
    font-size: 13.5px;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    min-width: 0;
  }
  .bad {
    color: var(--bad-fg);
  }
  .fp-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .fp {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 13px;
    overflow-wrap: anywhere;
  }
  .weak {
    margin-left: 6px;
    padding: 0 6px;
    border-radius: 999px;
    background: var(--warn-bg);
    border: 1px solid var(--warn-border);
    color: var(--warn-fg);
    font-size: 11px;
    font-weight: 600;
  }
  .needs {
    color: var(--warn-fg);
    font-weight: 600;
  }
  .uform {
    margin-top: 10px;
    padding: 12px 14px;
    border-radius: 16px;
    border: 1px solid var(--input-border);
  }
  .ugrid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 10px 14px;
  }
  .lbl {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13.5px;
    font-weight: 600;
  }
  .lbl .hint {
    font-weight: 400;
  }
  .ferr {
    margin: 2px 0 0;
    font-size: 13px;
    font-weight: 500;
    color: var(--bad-fg);
  }
  .done {
    margin: 0 0 10px;
    padding: 8px 12px;
    border-radius: 12px;
    border: 1px solid var(--info-border);
    background: var(--info-bg);
    font-size: 13.5px;
  }
  .fwbox {
    margin-bottom: 12px;
    padding: 10px 14px;
    border-radius: 14px;
    border: 1px solid var(--warn-border);
    background: var(--warn-bg);
  }
  .errs {
    margin: 4px 0 0;
    padding-left: 18px;
    font-size: 13px;
    list-style: disc;
  }
  .errs code,
  .hint code,
  .trouble code {
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
  .trouble {
    margin-top: 14px;
  }
  .trouble summary {
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
  }
  .trouble ul {
    margin: 8px 0 10px;
    padding-left: 20px;
    list-style: disc;
    font-size: 13.5px;
    line-height: 1.55;
  }
  .cmd {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 8px 8px 12px;
    border-radius: 14px;
  }
  .cmd code {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 12.5px;
    overflow-wrap: anywhere;
  }
  .lnk {
    border: 0;
    background: none;
    padding: 0 4px;
    color: var(--link, inherit);
    text-decoration: underline;
    cursor: pointer;
    font: inherit;
  }
  .lnk.bad {
    color: var(--bad-fg);
  }
  #snmp-users,
  #snmp-mibs,
  #snmp-failures {
    scroll-margin-top: 90px;
  }
  th {
    text-align: left;
    font-weight: 600;
    color: var(--muted);
    padding: 6px 10px;
    border-bottom: 1px solid var(--divider);
    position: sticky;
    top: 0;
    background: var(--glass-strong);
  }
  td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--divider);
    vertical-align: middle;
  }
  td.detail {
    overflow-wrap: break-word;
    min-width: 220px;
  }
</style>

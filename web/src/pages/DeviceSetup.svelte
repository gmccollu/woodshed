<script lang="ts">
  import { ApiError, getSetupFamilies, getSetupSnippet } from '../lib/api';
  import { router, setQuery } from '../lib/router.svelte';
  import {
    AUTHS,
    FACILITIES,
    PRIVS,
    SEVERITIES,
    TRANSPORT_LABEL,
    VERIFICATION_LABEL,
    WHAT_LABEL,
    activeChoices,
    formErrors,
    formQuery,
    newSetupForm,
    snippetBody,
    verificationText,
    type SetupFamily,
    type SetupForm,
    type Snippet,
    type Verification,
    type What,
  } from '../lib/setup';
  import CopyButton from '../components/CopyButton.svelte';
  import Icon from '../components/Icon.svelte';

  let families = $state<SetupFamily[]>([]);
  let loadError = $state('');
  let form = $state<SetupForm | null>(null);
  let snippet = $state<Snippet | null>(null);
  let snippetError = $state('');
  let errorField = $state('');
  let loading = $state(false);
  /** The address picker: one of the server's addresses, or "other" for the text box. Until the
   *  user picks one, the request leaves the address out and the picker follows the server's default. */
  let addrPick = $state('');
  let otherAddr = $state('');
  let addrChosen = $state(false);

  const fam = $derived(families.find((f) => f.id === form?.family));
  const choices = $derived(form ? activeChoices(fam, form) : []);
  const localErrors = $derived(form ? formErrors(fam, form) : {});
  /** The field with an error, the form's own first, else the server's. */
  const badField = $derived((Object.keys(localErrors)[0] as string | undefined) ?? errorField);
  const describedBy = (field: string) => (badField === field ? (field in localErrors ? `setup-err-${field}` : 'setup-error') : undefined);
  /** A short line for screen readers when the snippet changes (the card itself isn't a live region). */
  const status = $derived(
    snippetError
      ? `Couldn't make the snippet: ${snippetError}`
      : snippet && fam
        ? `Snippet for ${fam.label.replaceAll('`', '')}, ${WHAT_LABEL[snippet.what]}, ${TRANSPORT_LABEL[snippet.transport] ?? snippet.transport}: ${VERIFICATION_LABEL[snippet.verification]}.`
        : '',
  );

  // Open on the family and type in the URL (#/device-setup?family=rsyslog&what=syslog), else the first.
  getSetupFamilies()
    .then((fs) => {
      families = fs;
      const q = new URLSearchParams(router.query);
      const f = fs.find((x) => x.id === q.get('family')) ?? fs[0];
      if (!f) return;
      const nf = newSetupForm(f, (q.get('what') ?? undefined) as What | undefined);
      const tr = q.get('transport');
      if (tr && f.transports[nf.what]?.includes(tr)) nf.transport = tr;
      form = nf;
    })
    .catch((e) => (loadError = (e as Error).message));

  function pickFamily(f: SetupFamily) {
    if (!form || form.family === f.id) return;
    const keep = form;
    const nf = newSetupForm(f, keep.what);
    // Choices the user typed carry over to the next family.
    Object.assign(nf, {
      address: keep.address,
      sourceInterface: keep.sourceInterface,
      iface: keep.iface,
      severity: keep.severity,
      facility: keep.facility,
      v3User: keep.v3User,
      auth: keep.auth,
      priv: keep.priv,
    });
    if (f.transports[nf.what]?.includes(keep.transport)) nf.transport = keep.transport;
    form = nf;
  }

  function pickWhat(w: What) {
    if (!form || !fam) return;
    form.what = w;
    form.transport = fam.transports[w]?.[0] ?? '';
  }

  $effect(() => {
    if (!form) return;
    form.address = addrChosen ? (addrPick === 'other' ? otherAddr : addrPick) : '';
  });

  // Ask for the snippet whenever the form changes (typing is debounced).
  $effect(() => {
    if (!form) return;
    const body = snippetBody(fam, form);
    setQuery(formQuery(form));
    if (Object.keys(formErrors(fam, form)).length) return; // fixed in the form first
    const ctl = new AbortController();
    const timer = setTimeout(async () => {
      loading = true;
      try {
        const s = await getSetupSnippet(body, ctl.signal);
        snippet = s;
        snippetError = '';
        errorField = '';
        if (!addrChosen) addrPick = s.address; // the server's default, which follows the family and transport
      } catch (e) {
        if ((e as Error).name === 'AbortError') return;
        snippetError = (e as Error).message;
        errorField = e instanceof ApiError ? (Object.keys(e.fields)[0] ?? '') : '';
      } finally {
        loading = false;
      }
    }, 150);
    return () => {
      clearTimeout(timer);
      ctl.abort();
    };
  });

  const badgeClass: Record<Verification, string> = { tested: 'b-tested', lab_checked: 'b-lab', reference: 'b-ref' };
  const PART_KIND: Record<string, string> = { file: 'File', command: 'Run', cli: 'Device CLI', steps: 'Checklist' };
  // Notes that need action before the snippet works (a listener that's off) stand out.
  const urgent = (n: string) => /listener is off|doesn't receive flows|won't hear/.test(n);
  /** A note's `code` spans: odd segments are code. */
  const ticks = (s: string) => s.split('`');
</script>

{#snippet rich(text: string)}{#each ticks(text) as seg, i (i)}{#if i % 2}<code class="font-mono text-[0.92em]">{seg}</code>{:else}{seg}{/if}{/each}{/snippet}

<div class="mx-auto max-w-5xl space-y-4">
  <section class="card">
    <h1 class="m-0 text-2xl font-bold tracking-tight">Set up a device</h1>
    <p class="mt-1.5 mb-0 max-w-3xl text-[14px] text-muted">
      The configuration a device needs to send this Woodshed its syslog, SNMP traps and flows, or to let Woodshed poll it, filled in with
      this server's addresses and ports. Secrets are always placeholders such as &lt;COMMUNITY&gt;; nothing on the server changes.
    </p>
  </section>

  {#if loadError}
    <section class="card text-bad-fg" role="alert">Couldn't load the setup families: {loadError}</section>
  {:else if !form || !fam}
    <section class="card text-muted">Loading…</section>
  {:else}
    <section class="card">
      <fieldset class="m-0 border-0 p-0">
        <legend class="card-title">How the device is configured</legend>
        <div class="fams">
          {#each families as f (f.id)}
            <label class="fam" class:on={form.family === f.id}>
              <input class="sr-only" type="radio" name="setup-family" value={f.id} checked={form.family === f.id} onchange={() => pickFamily(f)} />
              <span class="font-semibold">{f.label.replaceAll('`', '')}</span>
              <span class="badge {badgeClass[f.verification]}">{VERIFICATION_LABEL[f.verification]}</span>
            </label>
          {/each}
        </div>
      </fieldset>
      <ul class="mt-3 mb-0 list-none space-y-1 p-0 text-[13px] text-muted">
        {#each fam.notes as n (n)}<li>{@render rich(n)}</li>{/each}
      </ul>
    </section>

    <section class="card">
      <div class="grid gap-4 md:grid-cols-2">
        <fieldset class="m-0 border-0 p-0">
          <legend class="card-title">What to set up</legend>
          <div class="seg">
            {#each fam.what as w (w)}
              <label class:on={form.what === w}>
                <input class="sr-only" type="radio" name="setup-what" value={w} checked={form.what === w} onchange={() => pickWhat(w)} />{WHAT_LABEL[w]}
              </label>
            {/each}
          </div>
        </fieldset>
        <fieldset class="m-0 border-0 p-0">
          <legend class="card-title">{form.what === 'syslog' || form.what === 'flow' ? 'Transport' : 'SNMP version'}</legend>
          <div class="seg">
            {#each fam.transports[form.what] ?? [] as tr (tr)}
              <label class:on={form.transport === tr}>
                <input class="sr-only" type="radio" name="setup-transport" value={tr} checked={form.transport === tr} onchange={() => (form!.transport = tr)} />{TRANSPORT_LABEL[tr] ?? tr}
              </label>
            {/each}
          </div>
        </fieldset>
      </div>

      <div class="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <label class="lab">
          <span>Woodshed's address, as the device reaches it</span>
          <select class="field" bind:value={addrPick} onchange={() => (addrChosen = true)} aria-invalid={badField === 'address'} aria-describedby={describedBy('address')}>
            {#each snippet?.addresses ?? [] as a (a)}<option value={a}>{a}</option>{/each}
            <option value="other">Another address or name…</option>
          </select>
        </label>
        {#if addrPick === 'other'}
          <label class="lab">
            <span>Address or DNS name</span>
            <input class="field font-mono" bind:value={otherAddr} placeholder="192.0.2.10" spellcheck="false" aria-invalid={badField === 'address'} aria-describedby={describedBy('address')} />
          </label>
        {/if}
        {#if choices.includes('source_interface')}
          <label class="lab">
            <span>Device's source interface (optional)</span>
            <input class="field font-mono" bind:value={form.sourceInterface} placeholder="e.g. mgmt0" spellcheck="false" aria-invalid={badField === 'source_interface'} aria-describedby={describedBy('source_interface')} />
          </label>
        {/if}
        {#if choices.includes('interface')}
          <label class="lab">
            <span>Interface to watch</span>
            <input class="field font-mono" bind:value={form.iface} placeholder="e.g. eth0" spellcheck="false" aria-invalid={badField === 'interface'} aria-describedby={describedBy('interface')} />
          </label>
        {/if}
        {#if choices.includes('severity')}
          <label class="lab">
            <span>Lowest severity to send</span>
            <select class="field" bind:value={form.severity}>
              {#each SEVERITIES as s (s.id)}<option value={s.id}>{s.label}</option>{/each}
            </select>
          </label>
        {/if}
        {#if choices.includes('facility')}
          <label class="lab">
            <span>Facility</span>
            <select class="field" bind:value={form.facility}>
              <option value="">{form.family === 'rsyslog' ? 'Every facility' : "The device's default"}</option>
              {#each FACILITIES as f (f)}<option value={f}>{f}</option>{/each}
            </select>
          </label>
        {/if}
        {#if choices.includes('agent_port')}
          <label class="lab">
            <span>Agent port</span>
            <input class="field font-mono" bind:value={form.agentPort} placeholder="161" inputmode="numeric" aria-invalid={badField === 'agent_port'} aria-describedby={describedBy('agent_port')} />
            {#if localErrors.agent_port}<span class="err" id="setup-err-agent_port">{localErrors.agent_port}</span>{/if}
          </label>
        {/if}
        {#if choices.includes('v3_user')}
          <label class="lab">
            <span>SNMPv3 user name</span>
            <input class="field font-mono" bind:value={form.v3User} placeholder="&lt;V3-USER&gt;" spellcheck="false" aria-invalid={badField === 'v3_user'} aria-describedby={describedBy('v3_user')} />
          </label>
        {/if}
        {#if choices.includes('auth')}
          <label class="lab">
            <span>Authentication</span>
            <select class="field" bind:value={form.auth}>
              {#each AUTHS as a (a.id)}<option value={a.id}>{a.label}</option>{/each}
            </select>
          </label>
        {/if}
        {#if choices.includes('priv')}
          <label class="lab">
            <span>Privacy</span>
            <select class="field" bind:value={form.priv}>
              {#each PRIVS as p (p.id)}<option value={p.id}>{p.label}</option>{/each}
            </select>
          </label>
        {/if}
      </div>
    </section>

    <p class="sr-only" role="status">{status}</p>
    <section class="card" aria-busy={loading}>
      {#if Object.keys(localErrors).length}
        <p class="m-0 text-muted">Fix the field marked above to see the snippet.</p>
      {:else if snippetError}
        <p class="m-0 text-bad-fg" id="setup-error">{snippetError}</p>
      {:else if snippet}
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2">
              <span class="badge {badgeClass[snippet.verification]}" data-verification={snippet.verification}>
                {#if snippet.verification === 'tested'}<Icon name="check" size={13} />{/if}{VERIFICATION_LABEL[snippet.verification]}
              </span>
              <span class="text-[13px] text-muted">{verificationText(snippet.verification, snippet.checked_on)}</span>
            </div>
            {#if snippet.verification_detail}<p class="mt-1 mb-0 max-w-3xl text-[13px] text-muted">{snippet.verification_detail}</p>{/if}
            <p class="mt-2 mb-0 text-[15px] font-semibold">{snippet.does}</p>
          </div>
          <CopyButton text={snippet.text} label="Copy all" name="Copy the whole snippet" />
        </div>

        {#if snippet.notes.some(urgent)}
          <ul class="urgent mt-3 mb-0 list-none space-y-1 rounded-2xl p-3 text-[14px]">
            {#each snippet.notes.filter(urgent) as n (n)}<li class="flex gap-2"><Icon name="alert" size={15} /><span>{@render rich(n)}</span></li>{/each}
          </ul>
        {/if}

        {#each snippet.parts as p, i (i)}
          <div class="mt-4">
            <div class="mb-1.5 flex flex-wrap items-center justify-between gap-2">
              <div class="text-[13px]">
                <span class="kind">{PART_KIND[p.kind]}</span>
                {#if p.path}<code class="font-mono font-semibold">{p.path}</code>{/if}
                <span class="text-muted">{p.title}</span>
              </div>
              <CopyButton text={p.text} name={`Copy: ${p.title}`} />
            </div>
            <pre class="log-panel snippet m-0 rounded-2xl p-4">{p.text}</pre>
          </div>
        {/each}

        <h3 class="card-title mt-5">Notes</h3>
        <!-- The reference-only sentence is next to the badge above, so it isn't repeated here. -->
        <ul class="m-0 list-disc space-y-1.5 pl-5 text-[14px]">
          {#each snippet.notes.filter((n) => !urgent(n) && !n.startsWith('Reference only:')) as n (n)}
            <li class:warnnote={n.startsWith('Before you turn on TCP or TLS')}>{@render rich(n)}</li>
          {/each}
        </ul>
        <p class="mt-4 mb-0 text-[14px]"><span class="font-semibold">Check that it worked:</span> {@render rich(snippet.check)}</p>
        <p class="mt-2 mb-0 text-[12.5px] text-muted">Follows: {snippet.reference}</p>
      {:else}
        <p class="m-0 text-muted">Loading…</p>
      {/if}
    </section>
  {/if}
</div>

<style>
  .fams {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 8px;
  }
  .fam {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 6px;
    text-align: left;
    padding: 10px 12px;
    border-radius: 16px;
    border: 1px solid var(--border);
    background: var(--glass);
    color: var(--fg);
    font: inherit;
    font-size: 14px;
    cursor: pointer;
  }
  .fam:has(input:focus-visible),
  .seg label:has(input:focus-visible) {
    outline: 2px solid var(--link);
    outline-offset: 2px;
  }
  .err {
    font-size: 12.5px;
    color: var(--bad-fg);
  }
  .fam.on {
    background: var(--chip);
    border-color: var(--link);
    box-shadow: var(--shadow-chip);
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    border-radius: 999px;
    padding: 2px 9px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid;
  }
  .b-tested {
    color: var(--ok-fg);
    border-color: var(--ok);
    background: transparent;
  }
  .b-lab {
    color: var(--link);
    background: var(--info-bg);
    border-color: var(--info-border);
  }
  .b-ref {
    color: var(--warn-fg);
    background: var(--warn-bg);
    border-color: var(--warn-border);
  }
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 3px;
  }
  .seg label {
    border: 0;
    background: transparent;
    color: var(--fg);
    padding: 6px 14px;
    border-radius: 999px;
    font: inherit;
    font-size: 13.5px;
    cursor: pointer;
  }
  .seg label.on {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
  .lab {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 13px;
    color: var(--muted);
  }
  .snippet {
    font-size: 13px;
    line-height: 1.6;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }
  .kind {
    display: inline-block;
    margin-right: 6px;
    padding: 1px 8px;
    border-radius: 999px;
    background: var(--chip);
    font-weight: 600;
    font-size: 12px;
  }
  .urgent {
    background: var(--warn-bg);
    border: 1px solid var(--warn-border);
    color: var(--fg);
  }
  .warnnote {
    color: var(--warn-fg);
    font-weight: 600;
  }
</style>

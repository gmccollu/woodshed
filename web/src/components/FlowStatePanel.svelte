<script lang="ts">
  // Settings → Flows, below the form: what the budget holds (GET /api/flows), each exporter's rate,
  // domains, sampling, templates and losses, and one exporter's template field list (GET
  // /api/flows/templates), so a user can find the enterprise IE that carries a rule ID and add it to
  // listeners.flow.rule_id_ies (SPEC §13.2.1: no standard IE carries one).
  import { getFlows, getFlowTemplates } from '../lib/api';
  import { ieKey, ieLabel, samplingText, short, type FlowState, type FlowTemplates } from '../lib/flows';
  import { ago, bytes, num } from '../lib/format';
  import { deviceName } from '../lib/status.svelte';

  let { reload = 0, ruleIes = [], onuse }: { reload?: number; ruleIes?: string[]; onuse: (key: string) => void } = $props();

  let st = $state<FlowState | null>(null);
  let error = $state('');
  let dev = $state('');
  let tpl = $state<FlowTemplates | null>(null);
  let tplError = $state('');

  $effect(() => {
    void reload;
    const c = new AbortController();
    getFlows(c.signal).then(
      (s) => {
        st = s;
        error = '';
        if (!dev && s.exporters.length) dev = s.exporters[0].device_id;
      },
      (x) => (x as Error).name !== 'AbortError' && (error = (x as Error).message),
    );
    return () => c.abort();
  });
  $effect(() => {
    if (!dev) return;
    const c = new AbortController();
    getFlowTemplates(dev, c.signal).then(
      (t) => ((tpl = t), (tplError = '')),
      (x) => (x as Error).name !== 'AbortError' && ((tpl = null), (tplError = (x as Error).message)),
    );
    return () => c.abort();
  });
  const skew = (ms: number) => (Math.abs(ms) < 1000 ? `${ms} ms` : `${Math.round(ms / 1000)} s`);
</script>

<div class="space-y-3" data-flow-state>
  {#if error}<p class="m-0 text-[13.5px] text-bad-fg" role="alert">{error}</p>{/if}
  {#if st}
    <div class="est" aria-live="polite">
      {#if st.budget.estimated_days !== null}
        The flow budget holds <b>about {st.budget.estimated_days} days of flows</b> at the current rate; it holds {bytes(st.budget.used_bytes)} of
        {bytes(st.budget.bytes)} now.
      {:else}
        The flow budget is {bytes(st.budget.bytes)}; it holds {bytes(st.budget.used_bytes)} now. There's no estimate until flows arrive.
      {/if}
    </div>
    {#if st.exporters.length}
      <table class="xt">
        <thead>
          <tr>
            <th scope="col">Exporter</th><th scope="col" class="r">Records a second</th><th scope="col">Domains and sampling</th><th scope="col" class="r">Templates</th>
            <th scope="col" class="r">Last 24 h</th><th scope="col">Clock</th>
          </tr>
        </thead>
        <tbody>
          {#each st.exporters as e (e.device_id)}
            <tr>
              <td><a class="text-link underline" href="#/device?id={encodeURIComponent(e.device_id)}">{deviceName(e.device_id)}</a></td>
              <td class="r">{num(e.records_per_sec)}</td>
              <td>{e.domains.map((d) => `${d.id}: ${samplingText(d.sampling)}`).join(', ')}</td>
              <td class="r">{e.domains.reduce((s, d) => s + d.templates, 0)}</td>
              <td class="r" title="late {e.counts_24h.late}, waiting for a template {e.counts_24h.no_template}, malformed {e.counts_24h.malformed}, duplicates {e.counts_24h.duplicates}">
                {short(e.counts_24h.records)} records{e.counts_24h.sequence_gaps ? `, ${num(e.counts_24h.sequence_gaps)} gaps` : ''}{e.counts_24h.no_template
                  ? `, ${num(e.counts_24h.no_template)} raw`
                  : ''}{e.counts_24h.malformed ? `, ${num(e.counts_24h.malformed)} malformed` : ''}
              </td>
              <td class:bad={e.time_source === 'received'}>{e.time_source === 'received' ? `off by ${skew(e.clock_skew_ms)}: received time used` : skew(e.clock_skew_ms)}</td>
            </tr>
          {/each}
        </tbody>
      </table>

      <div>
        <label class="flex flex-wrap items-center gap-2 text-[14px] font-semibold">
          Template fields of
          <select class="field w-auto" bind:value={dev}>
            {#each st.exporters as e (e.device_id)}<option value={e.device_id}>{deviceName(e.device_id)} ({e.device_id})</option>{/each}
          </select>
        </label>
        <p class="hint">
          Every field each template carries, as the exporter sent it. No standard field carries a rule or ACL ID; exporters that send one use an
          enterprise field (shown as enterprise number:element ID). Find it here and press Use as rule ID.
        </p>
        {#if tplError}<p class="m-0 text-[13.5px] text-bad-fg" role="alert">{tplError}</p>{/if}
        {#if tpl}
          {#each tpl.domains as d (d.id)}
            {#each d.templates as t (t.id)}
              <details class="tp" open={!t.options}>
                <summary>
                  Domain {d.id} · {t.options ? 'options template' : 'template'} {t.id} · {t.fields.length} fields · received {ago(t.received)}
                </summary>
                <ul class="fl">
                  {#each t.fields as f, i (i)}
                    <li>
                      <span class="font-mono">{ieLabel(f)}</span>
                      <span class="text-muted">{f.name ? `${f.pen}:${f.id}` : 'enterprise'} · {f.length === 65535 ? 'variable' : `${f.length} B`}</span>
                      {#if f.pen}
                        {#if ruleIes.includes(ieKey(f))}<span class="used">rule ID</span>
                        {:else}<button type="button" class="ghost-btn sm" onclick={() => onuse(ieKey(f))}>Use as rule ID</button>{/if}
                      {/if}
                    </li>
                  {/each}
                </ul>
              </details>
            {/each}
          {:else}
            <p class="hint">No templates from this exporter yet.</p>
          {/each}
        {/if}
      </div>
    {:else}
      <p class="hint m-0">No exporter has sent flows yet.</p>
    {/if}
  {/if}
</div>

<style>
  .est {
    padding: 10px 14px;
    border-radius: 14px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
    font-size: 14px;
  }
  .hint {
    font-size: 13px;
    color: var(--muted);
  }
  .xt {
    width: 100%;
    border-collapse: collapse;
    font-size: 13.5px;
  }
  .xt th {
    text-align: left;
    font-weight: 600;
    color: var(--muted);
    padding: 4px 10px 4px 0;
    border-bottom: 1px solid var(--border);
  }
  .xt td {
    padding: 4px 10px 4px 0;
    vertical-align: top;
  }
  .r {
    text-align: right !important;
    font-variant-numeric: tabular-nums;
  }
  .bad {
    color: var(--bad-fg);
    font-weight: 600;
  }
  .tp {
    margin-top: 6px;
    padding: 6px 10px;
    border: 1px solid var(--border);
    border-radius: 12px;
  }
  .tp summary {
    cursor: pointer;
    font-size: 13.5px;
  }
  .fl {
    list-style: none;
    margin: 6px 0 0;
    padding: 0;
    columns: 2 22rem;
    font-size: 13px;
  }
  .fl li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 2px 8px;
    padding: 2px 0;
    break-inside: avoid;
  }
  .sm {
    padding: 1px 8px;
    font-size: 12px;
  }
  .used {
    font-size: 12px;
    font-weight: 600;
    color: var(--ok-fg, var(--fg));
  }
</style>

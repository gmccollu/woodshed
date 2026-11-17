<script lang="ts">
  // The device page's Flows card (SPEC §13.3): what this exporter has sent (records stored, from
  // /api/devices), its rate, observation domains, sampling and templates, the last 24 hours'
  // losses (sequence gaps are loss before Woodshed, between the exporter and here), a clock
  // warning when its times are more than an hour off (its flows then use the received time), and
  // records whose own times were far from when they arrived (kept as sent; SPEC §13.10 decision 70).
  import { getFlows, type Device } from '../lib/api';
  import { samplingText, short, timeOffNow, timeOffWords, type FlowExporter } from '../lib/flows';
  import { ago, num } from '../lib/format';

  let { id, device }: { id: string; device: Device | null | undefined } = $props();

  let exp = $state<FlowExporter | null | undefined>(undefined);
  $effect(() => {
    const c = new AbortController();
    getFlows(c.signal).then(
      (s) => (exp = s.exporters.find((e) => e.device_id === id) ?? null),
      () => (exp = null), // a server without flows (1.x)
    );
    return () => c.abort();
  });
  const stored = $derived(device?.lines_by_type?.flow ?? 0);
  const skew = (ms: number) => (Math.abs(ms) < 1000 ? `${ms} ms` : Math.abs(ms) < 120_000 ? `${Math.round(ms / 1000)} s` : `${Math.round(ms / 60_000)} min`);
</script>

{#if exp || stored}
  <section class="card" data-flow-device aria-labelledby="fd-title">
    <div class="flex flex-wrap items-start gap-3">
      <h2 id="fd-title" class="m-0 grow text-[17px] font-bold">Flows</h2>
      <a class="ghost-btn" href="#/events?type=flow&dev={encodeURIComponent(id)}&r=1h">Flows in Events</a>
      <a class="ghost-btn" href="#/events?type=flow&dev={encodeURIComponent(id)}&r=1h&top=denied">Denied</a>
    </div>
    {#if exp?.time_source === 'received'}
      <p class="warn" role="status">
        This exporter's clock is {skew(exp.clock_skew_ms)} off, more than an hour, so its flows use the time Woodshed received them (its own times are kept
        with each record). Fix its clock (NTP).
      </p>
    {/if}
    {#if exp && timeOffNow(exp)}
      <p class="warn" role="status" data-flow-time-off>
        In the last hour this exporter sent records whose times are far from when they arrived: {timeOffWords(exp.time_offsets_1h)}. Its clock or uptime is
        probably wrong. They're kept as sent, so they show in Events at their own times.
      </p>
    {/if}
    <dl class="kv">
      <dt>Records stored</dt>
      <dd>{num(stored)}</dd>
      {#if exp}
        <dt>Rate</dt>
        <dd>{num(exp.records_per_sec)} records a second</dd>
        <dt>Observation domains</dt>
        <dd>
          {#each exp.domains as d, i (d.id)}{i ? '; ' : ''}{d.id}: {samplingText(d.sampling)}, {d.templates} template{d.templates === 1 ? '' : 's'}{d.last_template
              ? `, last ${ago(d.last_template)}`
              : ''}{/each}
        </dd>
        <dt>Last 24 hours</dt>
        <dd>
          {short(exp.counts_24h.records)} records · {num(exp.counts_24h.sequence_gaps)} sequence gaps · {num(exp.counts_24h.duplicates)} duplicates ·
          {num(exp.counts_24h.late)} late · {num(exp.counts_24h.no_template)} waiting for a template · {num(exp.counts_24h.malformed)} malformed
        </dd>
        {#if exp.pending_bytes}<dt>Waiting for a template</dt><dd>{num(exp.pending_bytes)} bytes</dd>{/if}
        <dt>Clock</dt>
        <dd>{skew(exp.clock_skew_ms)} from Woodshed's</dd>
        {#if timeOffWords(exp.time_offsets_24h)}
          <dt>Times off arrival</dt>
          <dd data-flow-time-24h>{timeOffWords(exp.time_offsets_24h)} in the last 24 hours (ahead: more than 1 h after arrival; behind: more than 24 h before)</dd>
        {/if}
      {:else if exp === null}
        <dt>Now</dt>
        <dd>Not exporting since the server started.</dd>
      {/if}
    </dl>
    <p class="hint m-0">
      Sequence gaps are records lost between the exporter and Woodshed (the network, or the exporter's own drops); Woodshed's own losses are counted as
      drops. Sampled counts are shown as exported and scaled, never one for the other.
    </p>
  </section>
{/if}

<style>
  .kv {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 18px;
    margin: 10px 0;
    font-size: 14px;
  }
  .kv dt {
    color: var(--muted);
  }
  .kv dd {
    margin: 0;
  }
  .hint {
    font-size: 13px;
    color: var(--muted);
  }
  .warn {
    margin: 8px 0 0;
    padding: 8px 12px;
    border-radius: 12px;
    background: var(--warn-bg);
    border: 1px solid var(--warn-border);
    color: var(--warn-fg);
    font-size: 13.5px;
  }
</style>

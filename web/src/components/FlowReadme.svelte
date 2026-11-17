<script lang="ts">
  // The bundle preview's look at each flow exporter's README Flows block (SPEC §13.4), built from
  // the same top-N the server's summary uses (GET /api/flows/top over the bundle's window) and
  // the exporters' state (GET /api/flows), so the user sees what the zip's README will say before
  // building it. The built bundle computes its own, and counts the window's sequence gaps; template
  // counts here, and the gaps line, are the last 24 hours'. Nothing shows when the bundle leaves
  // flows out or no exporter is in it.
  import { getFlowTop, getFlows } from '../lib/api';
  import { FLOW, flowReadme, type FlowBundleSummary, type FlowExporter, type FlowTopResponse } from '../lib/flows';
  import type { Scope } from '../lib/scope';
  import { deviceName, live } from '../lib/status.svelte';

  let { win, scope, types }: { win: { from: string; to: string }; scope: Scope; types: string[] } = $props();

  const MAX = 4;
  let blocks = $state<{ device: string; text: string }[]>([]);
  let more = $state(0);
  let busy = $state(false);

  const key = $derived(JSON.stringify({ win, scope, types }));
  $effect(() => {
    const k = JSON.parse(key) as { win: { from: string; to: string }; scope: Scope; types: string[] };
    if (k.types.length && !k.types.includes(FLOW)) {
      blocks = [];
      return;
    }
    const ctrl = new AbortController();
    build(k.win, k.scope, ctrl.signal);
    return () => ctrl.abort();
  });

  function inScope(id: string, s: Scope): boolean {
    if (s.mode === 'devices') return s.devices.includes(id);
    if (s.mode === 'group') return live.devices?.find((d) => d.id === id)?.group === s.group;
    if (s.mode === 'ungrouped') return !live.devices?.find((d) => d.id === id)?.group;
    return true;
  }

  async function build(w: { from: string; to: string }, s: Scope, signal: AbortSignal) {
    busy = true;
    try {
      const st = await getFlows(signal);
      const exp = st.exporters.filter((e) => inScope(e.device_id, s));
      const out: { device: string; text: string }[] = [];
      for (const e of exp.slice(0, MAX)) {
        const sum = await summaryOf(e, w, signal);
        if (sum) out.push({ device: e.device_id, text: flowReadme(sum) });
      }
      blocks = out;
      more = Math.max(0, exp.length - MAX);
    } catch {
      blocks = []; // a server without flows (1.x), or an aborted read
    } finally {
      busy = false;
    }
  }

  async function summaryOf(e: FlowExporter, w: { from: string; to: string }, signal: AbortSignal): Promise<FlowBundleSummary | null> {
    const top = (by: Parameters<typeof getFlowTop>[0]['by'], metric?: Parameters<typeof getFlowTop>[0]['metric'], filters?: Record<string, string[]>, n = 3) =>
      getFlowTop({ devices: [e.device_id], from: w.from, to: w.to, by, metric, filters, top: n, budget_ms: 10_000 }, signal);
    const [talk, ports, conv, fw, dsrc, dport, nat] = await Promise.all([
      top('src', 'bytes'),
      top('dst_port', 'bytes'),
      top('conversation', 'bytes', undefined, 1),
      top('fw_event', 'flows', undefined, 5),
      top('src', 'flows', { fw_event: ['denied'] }, 2),
      top('dst_port', 'flows', { fw_event: ['denied'] }, 2),
      top('post_nat_src', 'connections', undefined, 1),
    ]);
    if (!talk.total.flows) return null;
    const ev = (k: string) => fw.rows.find((r) => r.key === k)?.flows ?? 0;
    const shares = (r: FlowTopResponse) => r.rows.filter((x) => x.share > 0).map((x) => ({ key: x.key, share: x.share }));
    const counts = (r: FlowTopResponse) => r.rows.map((x) => ({ key: x.key, count: x.flows }));
    const natTotal = nat.rows.reduce((s, x) => s + (x.connections ?? x.flows), 0) + (nat.other.connections ?? nat.other.flows);
    return {
      records: talk.total.flows,
      domains: e.domains.length,
      sampling: e.domains.map((d) => ({ domain: d.id, sampling: d.sampling })),
      bytes: talk.total.bytes,
      bytes_scaled: e.domains.every((d) => d.sampling <= 1) ? null : talk.total.bytes_scaled,
      packets: talk.total.packets,
      packets_scaled: e.domains.every((d) => d.sampling <= 1) ? null : talk.total.packets_scaled,
      top_talkers: shares(talk),
      top_dst_ports: shares(ports),
      top_conversations: shares(conv),
      fw_events: { created: ev('created'), deleted: ev('deleted'), denied: ev('denied') },
      top_denied_sources: counts(dsrc),
      top_denied_ports: counts(dport),
      nat_connections: natTotal,
      top_post_nat_sources: nat.rows.map((x) => ({ key: x.key, share: natTotal ? (x.connections ?? x.flows) / natTotal : 0 })),
      zero_omitted: { top_talkers: talk.zero_omitted ?? 0, top_dst_ports: ports.zero_omitted ?? 0, top_conversations: conv.zero_omitted ?? 0 },
      // The window's gaps are counted when the bundle is built (decision 82); the collector's last 24 h stand in,
      // labelled as not the window's.
      sequence_gaps: null,
      lost_estimate: null,
      sequence_gaps_unknown: 'preview',
      sequence_gaps_24h: e.counts_24h.sequence_gaps,
      lost_estimate_24h: null,
      no_template: e.counts_24h.no_template,
      malformed: e.counts_24h.malformed,
      time_offsets: null,
      time_offsets_24h: e.time_offsets_24h ?? null,
    };
  }
</script>

{#if blocks.length}
  <section class="card" aria-labelledby="frd-title" data-flow-readme>
    <h2 id="frd-title" class="m-0 text-[16px] font-bold">Flows in the bundle's README</h2>
    <p class="mt-1 mb-2 text-[13px] text-muted">
      What each exporter's <span class="font-mono">README.txt</span> will say about its flows in this window. The bundle counts them again when it's
      built, sequence gaps in the window included; template counts and times off arrival here are the last 24 hours'.
    </p>
    {#each blocks as b (b.device)}
      <div class="dev">{deviceName(b.device)} <span class="font-mono text-muted">{b.device}</span></div>
      <pre class="rd">{b.text}</pre>
    {/each}
    {#if more}<p class="m-0 text-[13px] text-muted">and {more} more exporter{more === 1 ? '' : 's'}</p>{/if}
    {#if busy}<p class="m-0 text-[13px] text-muted">Updating…</p>{/if}
  </section>
{/if}

<style>
  .dev {
    margin-top: 6px;
    font-size: 13.5px;
    font-weight: 600;
  }
  .rd {
    margin: 4px 0 8px;
    padding: 10px 12px;
    border-radius: 12px;
    background: var(--log-bg, #11151b);
    color: var(--log-fg);
    font-size: 12.5px;
    line-height: 1.5;
    overflow-x: auto;
    white-space: pre;
  }
</style>

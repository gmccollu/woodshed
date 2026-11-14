<script lang="ts">
  // Poll strips under the Events histogram (SPEC §12.5), on its time axis and bucket edges: with
  // one polled device selected, its total in/out, CPU and errors (3 strips); with several, one
  // in/out strip each for at most 4 (the busiest), then "and N more". Restart and oper-change
  // markers of every selected device are vertical lines across the strips (and, through
  // onmarkers, the histogram); hovering one names the device and the source. Nothing shows when
  // no selected device is polled.
  import { getPollTimeline, type Histogram } from '../lib/api';
  import {
    aligned,
    capMarkers,
    inUnit,
    linePath,
    markerTitle,
    stripsOf,
    type PollMarker,
    type PollTimeline,
  } from '../lib/poll';
  import { deviceName } from '../lib/status.svelte';

  let {
    hist,
    from,
    to,
    scope,
    utc = false,
    onmarkers,
  }: {
    hist: Histogram | null;
    from: string;
    to: string;
    scope: { devices?: string[]; group?: string; ungrouped?: boolean };
    utc?: boolean;
    onmarkers?: (m: { left: number; title: string; kind: string }[]) => void;
  } = $props();

  let tl = $state<PollTimeline | null>(null);
  const bucket = $derived(hist?.bucket_seconds ?? 0);
  const scopeKey = $derived(JSON.stringify(scope));
  $effect(() => {
    if (!bucket) return;
    const ctrl = new AbortController();
    const s = JSON.parse(scopeKey) as typeof scope;
    getPollTimeline({ ...s, from, to, bucket }, ctrl.signal).then(
      (r) => (tl = r),
      () => (tl = null), // a server without the poller (1.2), or a failed read: no strips
    );
    return () => ctrl.abort();
  });

  const buckets = $derived(hist?.buckets ?? []);
  const n = $derived(buckets.length);
  const size = $derived(bucket * 1000);
  const span0 = $derived(n ? Date.parse(buckets[0].start) : 0);
  const leftOf = (iso: string) => ((Date.parse(iso) - span0) / (n * size)) * 100;
  const inSpan = (m: PollMarker) => n > 0 && Date.parse(m.time) >= span0 && Date.parse(m.time) < span0 + n * size;
  const nameOf = (id: string) => deviceName(id);

  const shownMarkers = $derived(capMarkers((tl?.markers ?? []).filter(inSpan)));
  $effect(() => {
    onmarkers?.(shownMarkers.shown.map((m) => ({ left: leftOf(m.time), title: markerTitle(m, m.device_id ? nameOf(m.device_id) : ''), kind: m.kind })));
  });

  const COLORS: Record<string, string> = { in_bps: 'var(--log-host)', out_bps: 'var(--sev-notice)', cpu: 'var(--sev-info)', errors_d: 'var(--sev-err)', discards_d: 'var(--sev-warn)' };
  const strips = $derived(
    (tl?.devices ?? []).flatMap((d) =>
      stripsOf(d.series).map((s) => {
        const lines = s.series.map((x) => ({
          key: x.key,
          label: x.key === 'in_bps' ? 'in' : x.key === 'out_bps' ? 'out' : x.label,
          color: COLORS[x.key] ?? 'var(--log-fg)',
          dash: x.key === 'out_bps',
          values: aligned(x.points, span0, size, n, x.key.endsWith('_d')),
        }));
        const peak = Math.max(0, ...lines.flatMap((l) => l.values.filter((v): v is number => v !== null)));
        return { device: d.device_id, key: s.key, label: s.label, unit: s.unit, lines, peak, top: s.unit === '%' ? 100 : (peak || 1) * 1.1 };
      }),
    ),
  );
  const single = $derived((tl?.devices.length ?? 0) === 1);

  let hover = $state<{ strip: number; i: number } | null>(null);
  function move(e: PointerEvent, k: number) {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    hover = { strip: k, i: Math.min(n - 1, Math.max(0, Math.floor(((e.clientX - r.left) / r.width) * n))) };
  }
  const pad = (x: number) => String(x).padStart(2, '0');
  const hhmm = (t: number) => {
    const d = new Date(t);
    return utc ? `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}` : `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
</script>

{#if strips.length && n}
  <div class="strips" aria-label="Poll data for the selected devices">
    {#each strips as s, k (s.device + s.key)}
      <div class="strip">
        <div class="lab">
          <span class="dev">{single && k > 0 ? '' : nameOf(s.device)}</span>
          <span>{s.label}</span>
          <span class="pk">peak {inUnit(s.unit, s.peak)}</span>
          {#each s.lines.length > 1 ? s.lines : [] as l (l.key)}<span class="lg"><span class="sw" class:dash={l.dash} style:border-color={l.color}></span>{l.label}</span>{/each}
        </div>
        <div class="plot" role="img" aria-label="{nameOf(s.device)} {s.label}, peak {inUnit(s.unit, s.peak)}" onpointermove={(e) => move(e, k)} onpointerleave={() => (hover = null)}>
          <svg viewBox="0 0 {n} 100" preserveAspectRatio="none" aria-hidden="true">
            {#each s.lines as l (l.key)}<path d={linePath(l.values, n, 100, s.top)} stroke={l.color} stroke-dasharray={l.dash ? '4 3' : undefined} />{/each}
          </svg>
          {#each shownMarkers.shown.filter((m) => !m.device_id || m.device_id === s.device || single) as m (m.time + m.kind + (m.if ?? '') + m.device_id)}
            <span class="mark {m.kind === 'restart' ? 'restart' : 'oper'}" style:left="{leftOf(m.time)}%" title={markerTitle(m, m.device_id ? nameOf(m.device_id) : '')}></span>
          {/each}
          {#if hover?.strip === k}
            <div class="tip" class:start={hover.i < n / 3} class:end={hover.i >= (n * 2) / 3} style:left="{((hover.i + 0.5) / n) * 100}%" role="status">
              {hhmm(span0 + hover.i * size)}–{hhmm(span0 + (hover.i + 1) * size)}{utc ? ' UTC' : ''}:
              {#each s.lines as l, j (l.key)}{j ? ', ' : ' '}{l.label} {l.values[hover.i] === null ? 'not measured' : inUnit(s.unit, l.values[hover.i])}{/each}
            </div>
          {/if}
        </div>
      </div>
    {/each}
    <div class="foot">
      {#if shownMarkers.shown.length}
        <span class="lg"><span class="mk restart"></span>restart</span>
        {#if shownMarkers.shown.some((m) => m.kind === 'oper')}<span class="lg"><span class="mk oper"></span>interface down or up</span>{/if}
      {/if}
      {#if shownMarkers.hidden}<span>+{shownMarkers.hidden} more markers not drawn</span>{/if}
      {#if tl?.more}<a class="more" href="#/devices?view=polled">and {tl.more} more polled device{tl.more === 1 ? '' : 's'}</a>{/if}
      <span class="grow"></span>
      <span>Gaps: not measured. Hover a line for its value, a marker for what happened.</span>
    </div>
  </div>
{/if}

<style>
  .strips {
    padding: 4px 18px 8px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    font-family: var(--font-sans);
    font-size: 12px;
    color: var(--log-dim);
  }
  .strip + .strip {
    margin-top: 4px;
  }
  .lab {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 2px 10px;
  }
  .dev {
    color: var(--log-fg);
    font-weight: 600;
  }
  .pk {
    font-variant-numeric: tabular-nums;
  }
  .plot {
    position: relative;
    height: 38px;
    margin-top: 2px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.12);
  }
  svg {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    overflow: visible;
  }
  path {
    fill: none;
    stroke-width: 1.5;
    stroke-linejoin: round;
    stroke-linecap: round;
    vector-effect: non-scaling-stroke;
  }
  .mark {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 7px;
    margin-left: -3px;
    z-index: 1;
    cursor: help;
  }
  .mark::before {
    content: '';
    position: absolute;
    left: 3px;
    top: 0;
    bottom: 0;
    border-left: 2px solid var(--sev-warn);
  }
  .mark.oper::before {
    border-left: 1.5px dashed var(--sev-unknown);
  }
  .lg {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .sw {
    display: inline-block;
    width: 14px;
    border-top: 2px solid;
  }
  .sw.dash {
    border-top-style: dashed;
  }
  .mk {
    display: inline-block;
    height: 11px;
    border-left: 2px solid var(--sev-warn);
  }
  .mk.oper {
    border-left: 1.5px dashed var(--sev-unknown);
  }
  .foot {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px 14px;
    margin-top: 6px;
  }
  .grow {
    flex-grow: 1;
  }
  .more {
    color: var(--log-host);
    text-decoration: underline;
  }
  .tip {
    position: absolute;
    bottom: calc(100% + 4px);
    transform: translateX(-50%);
    z-index: 3;
    padding: 3px 8px;
    border-radius: 6px;
    background: var(--log-bar);
    color: var(--log-fg);
    white-space: nowrap;
    pointer-events: none;
  }
  .tip.start {
    transform: translateX(-12px);
  }
  .tip.end {
    transform: translateX(calc(-100% + 12px));
  }
</style>

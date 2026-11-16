<script lang="ts">
  // The flow strip under the Events histogram on the other tabs (SPEC §13.3): for the selected
  // devices that export flows, bytes a second as exported (solid) and scaled by their sampling
  // (dashed, when it differs), from flow_minute, on the histogram's bucket edges. At most 4 (the
  // busiest), then "and N more". Nothing shows when no selected device exports flows, or on a
  // server without flows.
  import { getFlowTimeline, type Histogram } from '../lib/api';
  import { dbytes, type FlowTimeline } from '../lib/flows';
  import { linePath } from '../lib/poll';
  import { deviceName } from '../lib/status.svelte';

  let {
    hist,
    from,
    to,
    scope,
    utc = false,
  }: {
    hist: Histogram | null;
    from: string;
    to: string;
    scope: { devices?: string[]; group?: string; ungrouped?: boolean };
    utc?: boolean;
  } = $props();

  let tl = $state<FlowTimeline | null>(null);
  const bucket = $derived(hist?.bucket_seconds ?? 0);
  const scopeKey = $derived(JSON.stringify(scope));
  $effect(() => {
    if (!bucket) return;
    const ctrl = new AbortController();
    const s = JSON.parse(scopeKey) as typeof scope;
    getFlowTimeline({ ...s, from, to, bucket, metric: 'bytes' }, ctrl.signal).then(
      (r) => (tl = r),
      () => (tl = null),
    );
    return () => ctrl.abort();
  });

  const buckets = $derived(hist?.buckets ?? []);
  const n = $derived(buckets.length);
  const size = $derived(bucket * 1000);
  const span0 = $derived(n ? Date.parse(buckets[0].start) : 0);

  const strips = $derived(
    (tl?.devices ?? [])
      .map((d) => {
        const ex: (number | null)[] = Array(n).fill(null);
        const sc: (number | null)[] = Array(n).fill(null);
        let scaledDiffers = false;
        for (const p of d.points) {
          const i = Math.round((Date.parse(p.start) - span0) / size);
          if (i < 0 || i >= n) continue;
          ex[i] = p.bytes / bucket;
          sc[i] = p.bytes_scaled === null ? null : p.bytes_scaled / bucket;
          if (p.bytes_scaled !== null && p.bytes_scaled !== p.bytes) scaledDiffers = true;
        }
        const peak = Math.max(0, ...ex.filter((v): v is number => v !== null));
        const peakS = Math.max(0, ...sc.filter((v): v is number => v !== null));
        return { device: d.device_id, ex, sc: scaledDiffers ? sc : null, peak, peakS, top: Math.max(peak, scaledDiffers ? peakS : 0) * 1.1 || 1 };
      })
      .filter((s) => s.peak > 0 || s.peakS > 0),
  );
  const rate = (v: number | null) => (v === null ? 'none' : `${dbytes(v)}/s`);

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
  <div class="fstrips" aria-label="Flows exported by the selected devices" data-flow-strip>
    {#each strips as s, k (s.device)}
      <div class="fstrip">
        <div class="lab">
          <span class="dev">{deviceName(s.device)}</span>
          <span>Flows, bytes/s</span>
          <span class="pk">peak {rate(s.peak)}{s.sc ? `, ≈ ${rate(s.peakS)} scaled` : ''}</span>
          {#if s.sc}<span class="lg"><span class="sw"></span>exported</span><span class="lg"><span class="sw dash"></span>scaled</span>{/if}
        </div>
        <div class="plot" role="img" aria-label="{deviceName(s.device)} flows, peak {rate(s.peak)}" onpointermove={(e) => move(e, k)} onpointerleave={() => (hover = null)}>
          <svg viewBox="0 0 {n} 100" preserveAspectRatio="none" aria-hidden="true">
            <path d={linePath(s.ex, n, 100, s.top)} stroke="var(--sev-info)" />
            {#if s.sc}<path d={linePath(s.sc, n, 100, s.top)} stroke="var(--log-host)" stroke-dasharray="4 3" />{/if}
          </svg>
          {#if hover?.strip === k}
            <div class="tip" class:start={hover.i < n / 3} class:end={hover.i >= (n * 2) / 3} style:left="{((hover.i + 0.5) / n) * 100}%" role="status">
              {hhmm(span0 + hover.i * size)}–{hhmm(span0 + (hover.i + 1) * size)}{utc ? ' UTC' : ''}: {rate(s.ex[hover.i])} exported{s.sc ? `, ≈ ${rate(s.sc[hover.i])} scaled` : ''}
            </div>
          {/if}
        </div>
      </div>
    {/each}
    <div class="foot">
      {#if tl?.more}<span>and {tl.more} more exporter{tl.more === 1 ? '' : 's'}</span>{/if}
      <span class="grow"></span>
      <a class="more" href="#/events?type=flow&r=1h">Open Flows</a>
    </div>
  </div>
{/if}

<style>
  .fstrips {
    padding: 4px 18px 8px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    font-family: var(--font-sans);
    font-size: 12px;
    color: var(--log-dim);
  }
  .fstrip + .fstrip {
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
    height: 34px;
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
    vector-effect: non-scaling-stroke;
  }
  .lg {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .sw {
    display: inline-block;
    width: 14px;
    border-top: 2px solid var(--sev-info);
  }
  .sw.dash {
    border-top: 2px dashed var(--log-host);
  }
  .foot {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
    margin-top: 4px;
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

<script lang="ts">
  // One small line chart of poll series (the device page's Polling panel, SPEC §12.5): one value
  // per bucket, a gap where a bucket wasn't measured (never a drop to zero), the axis from 0 to a
  // rounded peak, restart and oper-change markers as vertical lines, and a hover readout of every
  // line at that bucket. The style follows the About page's queue chart.
  import { capMarkers, inUnit, linePath, markerTitle, niceCeil, type ChartLine, type PollMarker } from '../lib/poll';

  let {
    title,
    unit,
    lines,
    start,
    size,
    from,
    to,
    markers = [],
    utc = false,
    note = '',
    caption = '',
    fixedTop = 0,
  }: {
    title: string;
    unit: string;
    lines: ChartLine[];
    /** The first bucket's start and the bucket size, in ms. */
    start: number;
    size: number;
    from: string;
    to: string;
    markers?: PollMarker[];
    utc?: boolean;
    /** Shown instead of the chart when there's nothing to draw ("not available on this device"). */
    note?: string;
    /** A short line under the chart (what the numbers mean on some devices). */
    caption?: string;
    /** A fixed top for the axis (100 for percentages); 0 rounds up the peak. */
    fixedTop?: number;
  } = $props();

  const n = $derived(Math.max(1, ...lines.map((l) => l.values.length)));
  const peak = $derived(Math.max(0, ...lines.flatMap((l) => l.values.filter((v): v is number => v !== null))));
  const top = $derived(fixedTop || niceCeil(peak || 1));
  const measured = $derived(lines.some((l) => l.values.some((v) => v !== null)));

  const pad = (x: number) => String(x).padStart(2, '0');
  const multiDay = $derived(Date.parse(to) - Date.parse(from) > 86_400_000);
  function label(t: number): string {
    const d = new Date(t);
    const [mo, da, h, mi] = utc ? [d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes()] : [d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes()];
    const time = `${pad(h)}:${pad(mi)}`;
    return multiDay ? (h === 0 && mi === 0 ? `${pad(mo)}-${pad(da)}` : `${pad(mo)}-${pad(da)} ${time}`) : time;
  }
  const leftOf = (t: number) => ((t - start) / (n * size)) * 100;
  const ticks = $derived.by(() => {
    const k = Math.min(multiDay ? 3 : 4, n);
    return Array.from({ length: k }, (_, j) => {
      const i = Math.round((j * (n - 1)) / Math.max(1, k - 1));
      return { left: ((i + 0.5) / n) * 100, text: label(Math.max(start + i * size, Date.parse(from))) };
    });
  });

  const capped = $derived(capMarkers(markers.filter((m) => Date.parse(m.time) >= start && Date.parse(m.time) < start + n * size)));

  let box: HTMLDivElement | undefined = $state();
  let hover = $state<number | null>(null);
  function move(e: PointerEvent) {
    const r = box!.getBoundingClientRect();
    hover = Math.min(n - 1, Math.max(0, Math.floor(((e.clientX - r.left) / r.width) * n)));
  }
  const tipTime = (i: number) => `${label(Math.max(start + i * size, Date.parse(from)))}–${label(Math.min(start + (i + 1) * size, Date.parse(to)))}${utc ? ' UTC' : ''}`;

  const summary = $derived(
    note ||
      (measured
        ? `${title}: ${lines.map((l) => `${l.label} peak ${inUnit(unit, Math.max(...l.values.filter((v): v is number => v !== null)))}`).join('; ')}${capped.shown.length ? `; ${capped.shown.length} marker${capped.shown.length === 1 ? '' : 's'}` : ''}.`
        : `${title}: not measured in this range.`),
  );
</script>

<figure class="chartcard m-0">
  <figcaption class="head">
    <span class="t">{title}</span>
    {#if capped.hidden}<span class="more">+{capped.hidden} more markers</span>{/if}
  </figcaption>
  {#if note}
    <p class="note">{note}</p>
  {:else}
    <div class="chart" role="img" aria-label={summary}>
      <div class="axis" aria-hidden="true">
        <span>{inUnit(unit, top)}</span>
        <span>0</span>
      </div>
      <div class="plot" bind:this={box} onpointermove={move} onpointerleave={() => (hover = null)} role="presentation">
        <svg viewBox="0 0 {n} 100" preserveAspectRatio="none" aria-hidden="true">
          {#each lines as l, i (i)}
            <path d={linePath(l.values, n, 100, top)} stroke={l.color} stroke-dasharray={l.dash ? '5 3' : undefined} />
          {/each}
        </svg>
        {#each capped.shown as m (m.time + m.kind + (m.if ?? ''))}
          <span class="mark {m.kind === 'restart' ? 'restart' : 'oper'}" style:left="{leftOf(Date.parse(m.time))}%" title={markerTitle(m)}></span>
        {/each}
        {#if !measured}<span class="empty">Not measured in this range</span>{/if}
        {#if hover !== null}
          <span class="guide" style:left="{((hover + 0.5) / n) * 100}%" aria-hidden="true"></span>
          <div class="tip" class:start={hover < n / 3} class:end={hover >= (n * 2) / 3} style:left="{((hover + 0.5) / n) * 100}%" role="status">
            <div class="tt">{tipTime(hover)}</div>
            {#each lines as l, i (i)}
              <div class="tl"><span class="sw" class:dash={l.dash} style:border-color={l.color}></span>{l.label}: {l.values[hover] === null ? 'not measured' : inUnit(unit, l.values[hover])}</div>
            {/each}
          </div>
        {/if}
      </div>
      <span></span>
      <div class="ticks" aria-hidden="true">
        {#each ticks as t, j (j)}<span style:left="{t.left}%">{t.text}</span>{/each}
      </div>
    </div>
    <ul class="legend" aria-hidden="true">
      {#each lines as l, i (i)}<li><span class="sw" class:dash={l.dash} style:border-color={l.color}></span>{l.label}</li>{/each}
    </ul>
  {/if}
  {#if caption && !note}<p class="caption">{caption}</p>{/if}
</figure>

<style>
  .chartcard {
    min-width: 0;
  }
  .head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    font-size: 13px;
    font-weight: 600;
  }
  .more {
    font-size: 12px;
    font-weight: 400;
    color: var(--muted);
  }
  .caption {
    margin: 4px 0 0;
    font-size: 12px;
    color: var(--muted);
  }
  .note {
    margin: 8px 0 0;
    padding: 18px 12px;
    border: 1px dashed var(--divider);
    border-radius: 12px;
    font-size: 13px;
    color: var(--muted);
  }
  .chart {
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    grid-template-rows: 96px 18px;
    column-gap: 8px;
    row-gap: 2px;
    margin-top: 8px;
  }
  .axis {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    font-size: 11.5px;
    color: var(--muted);
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .plot {
    position: relative;
    border-bottom: 1px solid var(--divider);
    border-top: 1px dashed var(--divider);
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
    stroke-width: 1.75;
    stroke-linejoin: round;
    stroke-linecap: round;
    vector-effect: non-scaling-stroke;
  }
  .mark {
    position: absolute;
    top: -4px;
    bottom: 0;
    width: 7px;
    margin-left: -3px;
    cursor: help;
  }
  .mark::before {
    content: '';
    position: absolute;
    left: 3px;
    top: 0;
    bottom: 0;
    border-left: 2px solid var(--chart-mark);
  }
  .mark.oper::before {
    border-left: 1.5px dashed var(--muted);
  }
  .guide {
    position: absolute;
    top: 0;
    bottom: 0;
    border-left: 1px solid var(--muted);
    opacity: 0.5;
    pointer-events: none;
  }
  .empty {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    font-size: 12.5px;
    color: var(--muted);
  }
  .tip {
    position: absolute;
    bottom: calc(100% + 6px);
    transform: translateX(-50%);
    z-index: 3;
    padding: 5px 9px;
    border-radius: 8px;
    background: var(--btn);
    color: var(--btn-fg);
    font-size: 12px;
    white-space: nowrap;
    pointer-events: none;
  }
  .tip.start {
    transform: translateX(-12px);
  }
  .tip.end {
    transform: translateX(calc(-100% + 12px));
  }
  .tt {
    font-weight: 600;
    margin-bottom: 2px;
  }
  .tl .sw {
    border-top-width: 2px;
  }
  .ticks {
    position: relative;
    font-size: 11.5px;
    color: var(--muted);
  }
  .ticks span {
    position: absolute;
    transform: translateX(-50%);
    white-space: nowrap;
  }
  .ticks span:first-child {
    transform: none;
    left: 0 !important;
  }
  .ticks span:last-child {
    transform: translateX(-100%);
    left: 100% !important;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 12px;
    margin: 6px 0 0;
    padding: 0;
    list-style: none;
    font-size: 12px;
    color: var(--muted);
  }
  .sw {
    display: inline-block;
    width: 16px;
    margin-right: 5px;
    vertical-align: middle;
    border-top: 2.5px solid;
  }
  .sw.dash {
    border-top-style: dashed;
  }
</style>

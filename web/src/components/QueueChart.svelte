<script lang="ts">
  // The UDP receive queue's high-water mark per hour, oldest first (docs/api.md → UDP receive
  // queue), so stalls that recur at the same time of day, or at the top of the hour, stand out.
  // Hours that reached the capacity are drawn in the warning colour and labelled "full".
  import { num } from '../lib/format';

  let { values, capacity, now }: { values: number[]; capacity: number; now: number } = $props();

  const pad = (n: number) => String(n).padStart(2, '0');
  const hourStart = $derived(Math.floor(now / 3_600_000) * 3_600_000);
  /** The start of the i-th hour shown (the last is the current hour). */
  const startOf = (i: number) => hourStart - (values.length - 1 - i) * 3_600_000;
  const hh = (t: number) => `${pad(new Date(t).getHours())}:00`;

  const peak = $derived(Math.max(0, ...values));
  // On a capacity scale, a few hundred waiting would be invisible: scale to the peak unless it
  // reaches half the capacity, and only then draw the capacity line.
  const showCap = $derived(peak >= capacity / 2);
  const top = $derived(showCap ? capacity : niceCeil(Math.max(peak, 10)));
  function niceCeil(n: number): number {
    const p = 10 ** Math.floor(Math.log10(n));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= n) return m * p;
    return 10 * p;
  }
  const full = (v: number) => v >= capacity;
  function tip(i: number): string {
    const v = values[i];
    const span = `${hh(startOf(i))}–${hh(startOf(i) + 3_600_000)}${i === values.length - 1 ? ' (now)' : ''}`;
    return `${span}: at most ${num(v)} waiting${full(v) ? ' — the queue was full' : ''}`;
  }
  let hover = $state<number | null>(null);
  const ticks = $derived(values.map((_, i) => i).filter((i) => new Date(startOf(i)).getHours() % 6 === 0));
  const summary = $derived(
    values.length
      ? `Most messages waiting per hour over the last ${values.length} ${values.length === 1 ? 'hour' : 'hours'}: peak ${num(peak)} of ${num(capacity)}${values.some(full) ? `, full in ${values.filter(full).length}` : ''}.`
      : 'No data yet.',
  );
</script>

<figure class="m-0">
  <figcaption class="sr-only">{summary}</figcaption>
  <div class="chart" role="img" aria-label={summary}>
    <div class="axis" aria-hidden="true">
      <span>{num(top)}</span>
      <span>0</span>
    </div>
    <div class="plot" onpointerleave={() => (hover = null)} role="presentation">
      {#if showCap}<div class="cap" aria-hidden="true"></div>{/if}
      {#each values as v, i (i)}
        <div class="col" class:on={hover === i} role="presentation" onpointerenter={() => (hover = i)}>
          {#if full(v)}<span class="full" style:bottom="{(v / top) * 100}%">full</span>{/if}
          {#if v > 0}<span class="bar" class:warn={full(v)} style:height="{Math.max(2, (v / top) * 100)}%"></span>{/if}
        </div>
      {/each}
      {#if hover !== null}
        <div
          class="tip"
          class:start={hover < values.length / 4}
          class:end={hover >= (values.length * 3) / 4}
          role="status"
          style:left="{((hover + 0.5) / values.length) * 100}%"
        >
          {tip(hover)}
        </div>
      {/if}
    </div>
    <span></span>
    <div class="ticks" aria-hidden="true">
      {#each ticks as i (i)}<span style:left="{((i + 0.5) / values.length) * 100}%">{hh(startOf(i))}</span>{/each}
    </div>
  </div>
  <p class="legend" aria-hidden="true">
    Each bar: the most messages waiting at once in that hour (local time).
    {#if showCap}<span class="whitespace-nowrap"><span class="dash"></span> capacity ({num(capacity)})</span>{/if}
  </p>
  <details class="mt-2 text-[13px]">
    <summary class="cursor-pointer text-muted">Show as a table</summary>
    <table class="mt-2 w-full text-left">
      <thead><tr><th>Hour</th><th class="text-right">Most waiting</th></tr></thead>
      <tbody>
        {#each values as v, i (i)}
          <tr>
            <td>{hh(startOf(i))}–{hh(startOf(i) + 3_600_000)}{i === values.length - 1 ? ' (now)' : ''}</td>
            <td class="text-right tabular-nums">{num(v)}{full(v) ? ' (full)' : ''}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </details>
</figure>

<style>
  .chart {
    display: grid;
    grid-template-columns: max-content 1fr;
    grid-template-rows: 120px 18px;
    column-gap: 8px;
    row-gap: 2px;
    margin-top: 30px;
  }
  .legend {
    margin: 4px 0 0;
    font-size: 12.5px;
    color: var(--muted);
  }
  .dash {
    display: inline-block;
    width: 18px;
    vertical-align: middle;
    border-top: 1px dashed var(--muted);
    margin-left: 6px;
  }
  .axis {
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    font-size: 12px;
    color: var(--muted);
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .plot {
    position: relative;
    display: flex;
    align-items: stretch;
    gap: 2px;
    border-bottom: 1px solid var(--divider);
  }
  .cap {
    position: absolute;
    left: 0;
    right: 0;
    top: 0;
    border-top: 1px dashed var(--muted);
    pointer-events: none;
  }
  .col {
    position: relative;
    flex: 1 1 0;
    min-width: 0;
    border-radius: 4px 4px 0 0;
  }
  .col.on {
    background: var(--divider);
  }
  .bar {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--spark);
    border-radius: 4px 4px 0 0;
  }
  .bar.warn {
    background: var(--warn);
  }
  .full {
    position: absolute;
    left: 50%;
    transform: translate(-50%, -2px);
    font-size: 10.5px;
    font-weight: 600;
    color: var(--warn-fg);
    white-space: nowrap;
    pointer-events: none;
  }
  .tip {
    position: absolute;
    bottom: calc(100% + 6px);
    transform: translateX(-50%);
    z-index: 2;
    padding: 4px 8px;
    border-radius: 8px;
    background: var(--btn);
    color: var(--btn-fg);
    font-size: 12.5px;
    white-space: nowrap;
    pointer-events: none;
  }
  .tip.start {
    transform: translateX(-12px);
  }
  .tip.end {
    transform: translateX(calc(-100% + 12px));
  }
  .ticks {
    position: relative;
    font-size: 12px;
    color: var(--muted);
  }
  .ticks span {
    position: absolute;
    transform: translateX(-50%);
  }
  th {
    font-weight: 600;
    color: var(--muted);
  }
  td,
  th {
    padding: 2px 4px;
    border-bottom: 1px solid var(--divider);
  }
</style>

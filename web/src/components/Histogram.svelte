<script lang="ts">
  // Matches per time bucket for the current query (SPEC §10.1.2). Dragging across it picks a
  // range snapped to bucket edges; a click picks one bucket. Buckets the scan hasn't reached
  // yet (count null) are hatched; buckets spread from the index's checkpoints say "≈" in
  // their tooltip only.
  //
  // With `onpoint`, "Bundle around a moment" in the header switches to picking a point: the next
  // click (or Enter on a bar) picks the time under the pointer, rounded down to the minute (to the
  // second for buckets under a minute; a bar's start from the keyboard), and Esc cancels. Dragging
  // works as before outside that mode. `mark` draws a line at a moment (the bundle's).
  import type { Histogram } from '../lib/api';
  import { pointTime } from '../lib/bundle';
  import { snapSelection } from '../lib/events';
  import { num } from '../lib/format';

  let {
    hist,
    from,
    to,
    utc = false,
    busy = false,
    onselect,
    onpoint,
    pointLabel = 'Bundle around a moment',
    cursorText = 'Bundle around',
    mark = null,
    hint = 'Drag across the bars to zoom in; Back zooms out.',
  }: {
    hist: Histogram | null;
    from: string;
    to: string;
    utc?: boolean;
    busy?: boolean;
    onselect: (from: string, to: string) => void;
    /** A point picked in "Bundle around a moment" mode (RFC 3339). */
    onpoint?: (at: string) => void;
    pointLabel?: string;
    /** The words before the time on the line that follows the pointer while picking. */
    cursorText?: string;
    /** A moment to mark with a line (RFC 3339), or null. */
    mark?: string | null;
    hint?: string;
  } = $props();

  const pad = (n: number) => String(n).padStart(2, '0');
  function label(t: number, withDay: boolean, withSec: boolean): string {
    const d = new Date(t);
    const [mo, da, h, mi, s] = utc
      ? [d.getUTCMonth() + 1, d.getUTCDate(), d.getUTCHours(), d.getUTCMinutes(), d.getUTCSeconds()]
      : [d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()];
    const day = `${pad(mo)}-${pad(da)}`;
    const time = `${pad(h)}:${pad(mi)}${withSec ? `:${pad(s)}` : ''}`;
    return withDay ? (h === 0 && mi === 0 ? day : `${day} ${time}`) : time;
  }

  const buckets = $derived(hist?.buckets ?? []);
  const size = $derived((hist?.bucket_seconds ?? 60) * 1000);
  const max = $derived(Math.max(1, ...buckets.map((b) => b.count ?? 0)));
  const multiDay = $derived(Date.parse(to) - Date.parse(from) > 86_400_000);
  const withSec = $derived((hist?.bucket_seconds ?? 60) < 60);
  const sizeText = $derived.by(() => {
    const s = hist?.bucket_seconds ?? 0;
    if (s >= 86400) return `${s / 86400} d`;
    if (s >= 3600) return `${s / 3600} h`;
    if (s >= 60) return `${s / 60} min`;
    return `${s} s`;
  });

  function tip(i: number): string {
    const b = buckets[i];
    const a = Math.max(Date.parse(b.start), Date.parse(from));
    const e = Math.min(Date.parse(b.start) + size, Date.parse(to));
    const when = `${label(a, multiDay, withSec)}–${label(e, multiDay, withSec)}${utc ? ' UTC' : ''}`;
    if (b.count === null) return `${when}: not counted yet`;
    return `${when}: ${b.approx ? '≈ ' : ''}${num(b.count)} line${b.count === 1 ? '' : 's'}${b.approx ? ' (estimated from the index)' : ''}`;
  }

  const ticks = $derived.by(() => {
    const n = buckets.length;
    if (!n) return [];
    const k = Math.min(5, n);
    const out: { left: number; text: string }[] = [];
    for (let j = 0; j < k; j++) {
      const i = Math.round((j * (n - 1)) / Math.max(1, k - 1));
      out.push({ left: ((i + 0.5) / n) * 100, text: label(Math.max(Date.parse(buckets[i].start), Date.parse(from)), multiDay, withSec) });
    }
    return out;
  });

  // ----- drag to pick a range -----
  let box: HTMLDivElement | undefined = $state();
  let drag = $state<{ a: number; b: number } | null>(null);

  function indexAt(e: PointerEvent): number {
    const r = box!.getBoundingClientRect();
    const x = Math.min(Math.max(e.clientX - r.left, 0), r.width - 1);
    return Math.floor((x / r.width) * buckets.length);
  }
  // ----- pick a point -----
  let picking = $state(false);
  let hover = $state<number | null>(null);
  function fracAt(e: PointerEvent): number {
    const r = box!.getBoundingClientRect();
    return Math.min(Math.max((e.clientX - r.left) / r.width, 0), 1);
  }
  const timeAt = (frac: number) => pointTime(buckets[0].start, hist!.bucket_seconds, buckets.length, frac, from, to);
  function pick(at: string) {
    picking = false;
    hover = null;
    onpoint?.(at);
  }
  $effect(() => {
    if (!picking) return;
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        picking = false;
        hover = null;
      }
    };
    addEventListener('keydown', esc, true);
    return () => removeEventListener('keydown', esc, true);
  });
  const hoverAt = $derived(picking && hover !== null && buckets.length && hist ? timeAt(hover) : '');
  const span0 = $derived(buckets.length ? Date.parse(buckets[0].start) : 0);
  const spanMs = $derived(buckets.length * size);
  const leftOf = (iso: string) => ((Date.parse(iso) - span0) / spanMs) * 100;
  const markLeft = $derived(mark && spanMs && Date.parse(mark) >= Date.parse(from) && Date.parse(mark) <= Date.parse(to) ? leftOf(mark) : null);

  function down(e: PointerEvent) {
    if (!buckets.length || e.button !== 0) return;
    if (picking) {
      pick(timeAt(fracAt(e)));
      return;
    }
    try {
      box!.setPointerCapture(e.pointerId);
    } catch {
      /* a synthetic event (tests) has no active pointer */
    }
    const i = indexAt(e);
    drag = { a: i, b: i };
  }
  function move(e: PointerEvent) {
    if (picking) hover = fracAt(e);
    else if (drag) drag = { a: drag.a, b: indexAt(e) };
  }
  function up() {
    if (!drag || !hist) return;
    const { a, b } = drag;
    drag = null;
    const r = snapSelection(buckets.map((x) => x.start), hist.bucket_seconds, a, b, from, to);
    if (Date.parse(r.from) < Date.parse(r.to) && (r.from !== from || r.to !== to)) onselect(r.from, r.to);
  }
  function key(e: KeyboardEvent, i: number) {
    if ((e.key === 'Enter' || e.key === ' ') && hist && picking) {
      e.preventDefault();
      pick(new Date(Math.max(Date.parse(buckets[i].start), Date.parse(from))).toISOString().replace(/\.000Z$/, 'Z'));
      return;
    }
    if ((e.key === 'Enter' || e.key === ' ') && hist) {
      e.preventDefault();
      const r = snapSelection(buckets.map((x) => x.start), hist.bucket_seconds, i, i, from, to);
      onselect(r.from, r.to);
    }
  }
  const sel = $derived(drag ? { lo: Math.min(drag.a, drag.b), hi: Math.max(drag.a, drag.b) } : null);
</script>

<div class="histwrap" aria-busy={busy}>
  <div class="head">
    <span>Matches over time{hist ? ` · ${sizeText} buckets` : ''}</span>
    {#if hist?.source === 'index'}<span class="src" title="Counted from the index (per-minute and hourly stats, and file checkpoints), without reading the log files">from the index</span>{/if}
    {#if hist && buckets.some((b) => b.count === null)}<span class="legend"><span class="sw hatch" aria-hidden="true"></span>not counted yet</span>{/if}
    <span class="grow"></span>
    {#if hist}<span class="hint">{picking ? 'Click the moment on the bars (or Enter on one); Esc cancels.' : hint}</span>{/if}
    {#if onpoint && hist && buckets.length}
      <button type="button" class="pick" aria-pressed={picking} onclick={() => ((picking = !picking), (hover = null))} title="Then click a point on the bars">
        {picking ? 'Cancel' : pointLabel}
      </button>
    {/if}
  </div>
  <div
    class="hist"
    class:empty={!hist}
    class:picking
    bind:this={box}
    role="presentation"
    onpointerdown={down}
    onpointermove={move}
    onpointerup={up}
    onpointerleave={() => (hover = null)}
    onpointercancel={() => (drag = null)}
  >
    {#if markLeft !== null}<span class="mark" style:left="{markLeft}%" title="The bundle's moment" aria-hidden="true"></span>{/if}
    {#if hoverAt}
      <span class="cursor" style:left="{leftOf(hoverAt)}%" aria-hidden="true"
        ><span class="clabel" class:flip={leftOf(hoverAt) > 70}>{cursorText} {label(Date.parse(hoverAt), multiDay, withSec)}{utc ? ' UTC' : ''}</span></span
      >
    {/if}
    {#each buckets as b, i (b.start)}
      <button
        type="button"
        class="bar"
        class:pending={b.count === null}
        class:sel={sel && i >= sel.lo && i <= sel.hi}
        tabindex={i === 0 ? 0 : -1}
        title={tip(i)}
        aria-label={tip(i)}
        onkeydown={(e) => key(e, i)}
      >
        {#if b.count === null}<span class="fill hatch" style:height="100%"></span>
        {:else if b.count > 0}<span class="fill" style:height="{Math.max(3, (b.count / max) * 100)}%"></span>{/if}
      </button>
    {/each}
  </div>
  <div class="ticks" aria-hidden="true">
    {#each ticks as t, j (j)}<span style:left="{t.left}%">{t.text}</span>{/each}
  </div>
</div>

<style>
  .histwrap {
    padding: 8px 18px 4px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    font-family: var(--font-sans);
    font-size: 12.5px;
    color: var(--log-dim);
  }
  .head {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    margin-bottom: 6px;
  }
  .grow {
    flex-grow: 1;
  }
  .src {
    color: var(--log-fg);
  }
  .legend {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .sw {
    display: inline-block;
    width: 14px;
    height: 10px;
    border-radius: 2px;
  }
  .hist {
    position: relative;
    display: flex;
    align-items: stretch;
    gap: 1px;
    height: 76px;
    cursor: crosshair;
    touch-action: none;
    user-select: none;
  }
  .hist.empty {
    background: rgba(255, 255, 255, 0.04);
    border-radius: 6px;
  }
  .bar {
    position: relative;
    flex: 1 1 0;
    min-width: 0;
    padding: 0;
    border: 0;
    background: transparent;
    cursor: crosshair;
    border-radius: 2px 2px 0 0;
  }
  .bar:hover,
  .bar:focus-visible {
    background: rgba(255, 255, 255, 0.08);
  }
  .bar.sel {
    background: rgba(157, 188, 255, 0.22);
  }
  .fill {
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--log-host);
    border-radius: 2px 2px 0 0;
  }
  .hatch {
    background: repeating-linear-gradient(135deg, rgba(255, 255, 255, 0.16) 0 3px, transparent 3px 7px);
  }
  .ticks {
    position: relative;
    height: 18px;
    margin-top: 3px;
    font-family: var(--font-mono);
    font-size: 11.5px;
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
  .hint {
    font-size: 12px;
  }
  .pick {
    padding: 2px 10px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.18);
    background: transparent;
    color: var(--log-fg);
    font-size: 12.5px;
    cursor: pointer;
  }
  .pick:hover,
  .pick[aria-pressed='true'] {
    background: rgba(255, 255, 255, 0.12);
  }
  .hist.picking,
  .hist.picking .bar {
    cursor: copy;
  }
  .mark,
  .cursor {
    position: absolute;
    top: 0;
    bottom: 0;
    width: 0;
    border-left: 2px solid var(--sev-warn);
    z-index: 2;
    pointer-events: none;
  }
  .cursor {
    border-left-style: dashed;
    border-left-color: var(--log-fg);
  }
  .clabel {
    position: absolute;
    top: 2px;
    left: 6px;
    padding: 1px 6px;
    border-radius: 6px;
    background: var(--log-bar);
    color: var(--log-fg);
    font-size: 12px;
    white-space: nowrap;
  }
  .clabel.flip {
    left: auto;
    right: 6px;
  }
</style>

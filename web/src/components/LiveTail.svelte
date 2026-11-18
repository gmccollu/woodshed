<script lang="ts">
  import { tick } from 'svelte';
  import { openLive, type LogLine, type SampledNotice, type SevKey } from '../lib/api';
  import { clock, num } from '../lib/format';
  import { sevClass, sevLabel } from '../lib/severity';
  import { deviceName } from '../lib/status.svelte';
  import { splitRaw } from '../lib/syslog';
  import { prefs } from '../lib/prefs.svelte';
  import Icon from './Icon.svelte';
  import SeverityChips from './SeverityChips.svelte';
  import LogText from './LogText.svelte';
  import Marks from './Marks.svelte';
  import { openMenu } from '../lib/block.svelte';
  import { tip } from '../lib/logtext';

  let {
    group = '',
    ungrouped = false,
    devices = [],
    q = '',
    scope = 'all devices',
    onClearScope,
    eventsHref,
    height = '560px',
  }: {
    group?: string;
    ungrouped?: boolean;
    devices?: string[];
    q?: string;
    scope?: string;
    onClearScope?: () => void;
    /** "Open in Events": the stored history for what the tail shows. */
    eventsHref?: string;
    height?: string;
  } = $props();

  /** Lines kept in the DOM. Older lines drop off the top. */
  const MAX = 1000;
  /** The host column fits the longest visible name, up to this many characters. */
  const HOST_MAX = 28;

  interface Row extends LogLine {
    k: number;
    pri: string;
    header: string;
    body: string;
  }

  let paused = $state(false);
  /** Show each line exactly as received, PRI and header included. */
  let showRaw = $state(false);
  let full = $state(false);
  let rows = $state.raw<Row[]>([]);
  let heldCount = $state(0);
  let sampled = $state<SampledNotice | null>(null);
  let conn = $state<'connecting' | 'open' | 'error' | 'closed'>('connecting');
  /** Bumped to reopen a stream the browser closed for good (it won't retry after a 401 or 5xx). */
  let attempt = $state(0);
  let qDebounced = $state('');
  // String keys, so a new array with the same values doesn't reconnect.
  const devKey = $derived(devices.join(','));
  const sevKey = $derived(prefs.tailSev.join(','));
  const noLevels = $derived(!prefs.tailSev.length);
  let scroller: HTMLDivElement | undefined = $state();

  let pending: Row[] = [];
  let seq = 0;
  let flushTimer = 0;
  let reopen = 0;
  let sampledAt = 0;

  $effect(() => {
    const v = q;
    const t = setTimeout(() => (qDebounced = v.trim()), 300);
    return () => clearTimeout(t);
  });

  const hostCh = $derived.by(() => {
    let w = 8;
    for (const id of new Set(rows.map((r) => r.device_id))) w = Math.max(w, deviceName(id).length);
    return Math.min(w, HOST_MAX);
  });

  function toRow(l: LogLine): Row {
    return { ...l, k: seq++, ...splitRaw(l.raw) };
  }

  async function flush() {
    flushTimer = 0;
    if (paused || !pending.length) return;
    const el = scroller;
    const stick = !el || el.scrollHeight - el.scrollTop - el.clientHeight < 48;
    const next = rows.length + pending.length > MAX ? rows.concat(pending).slice(-MAX) : rows.concat(pending);
    pending = [];
    rows = next;
    if (stick && el) {
      await tick();
      el.scrollTop = el.scrollHeight;
    }
  }

  function schedule() {
    if (!flushTimer && !paused) flushTimer = window.setTimeout(flush, 100);
  }

  // Reconnect whenever a filter changes. The server applies the filters and replays
  // up to 200 matching lines from its ring buffer on connect.
  $effect(() => {
    void attempt;
    const sev = (sevKey ? sevKey.split(',').map((x) => (x === 'unknown' ? x : Number(x))) : []) as SevKey[];
    rows = [];
    pending = [];
    heldCount = 0;
    sampled = null;
    // Nothing selected is sent as severities=none: the stream stays open and sends nothing.
    conn = 'connecting';
    const close = openLive(
      {
        group: group || undefined,
        ungrouped,
        devices: devKey ? devKey.split(',') : undefined,
        severities: sev,
        q: qDebounced || undefined,
      },
      {
        onMessage(l) {
          pending.push(toRow(l));
          if (pending.length > MAX) pending.splice(0, pending.length - MAX);
          if (paused) heldCount++;
          else schedule();
        },
        onSampled(s) {
          sampled = s;
          sampledAt = Date.now();
        },
        onState(s) {
          conn = s;
          if (s === 'closed') reopen = window.setTimeout(() => attempt++, 3000);
        },
      },
    );
    const staleSample = setInterval(() => {
      if (sampled && Date.now() - sampledAt > 2500) sampled = null;
    }, 1000);
    return () => {
      close();
      clearInterval(staleSample);
      clearTimeout(flushTimer);
      clearTimeout(reopen);
      flushTimer = 0;
    };
  });

  $effect(() => {
    if (!full) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') full = false;
    };
    addEventListener('keydown', onKey);
    return () => removeEventListener('keydown', onKey);
  });

  function togglePause() {
    paused = !paused;
    if (!paused) {
      heldCount = 0;
      flush();
    }
  }

  function clear() {
    rows = [];
    pending = [];
    heldCount = 0;
  }
</script>

<section class="log-panel tail flex flex-col overflow-hidden" class:full style:height={full ? undefined : height} aria-label="Live tail">
  <div class="bar flex flex-col gap-2 border-b border-white/10 px-[18px] py-2.5 font-sans text-[13px]">
    <div class="flex flex-wrap items-center gap-x-2 gap-y-2">
      <div class="flex min-w-0 grow basis-40 items-center gap-2">
        <span
          class="inline-block size-2 shrink-0 rounded-full"
          style:background={paused || noLevels ? 'var(--sev-warn)' : conn === 'open' ? 'var(--sev-info)' : 'var(--sev-err)'}
          aria-hidden="true"
        ></span>
        <b class="text-white">Live tail</b>
        <span class="truncate text-log-dim">· {scope}{qDebounced ? ` · matching “${qDebounced}”` : ''}</span>
        {#if onClearScope}
          <button class="tail-btn" onclick={onClearScope} aria-label="Show all devices"><Icon name="x" size={13} /></button>
        {/if}
      </div>
      {#if eventsHref}
        <a class="tail-btn" href={eventsHref} title="Search the stored history (last hour) with these devices, severities and text">
          <Icon name="search" size={14} />Open in Events
        </a>
      {/if}
      <button class="tail-btn" onclick={togglePause} aria-pressed={paused}>
        <Icon name={paused ? 'play' : 'pause'} size={14} />{paused ? 'Resume' : 'Pause'}
      </button>
      <button class="tail-btn" onclick={() => (prefs.wrap = !prefs.wrap)} aria-pressed={prefs.wrap} title="Wrap long lines">Wrap</button>
      <button class="tail-btn" onclick={() => (showRaw = !showRaw)} aria-pressed={showRaw} title="Show the PRI and syslog header too">Raw</button>
      <button class="tail-btn" onclick={clear}><Icon name="clear" size={14} />Clear</button>
      <button class="tail-btn" onclick={() => (full = !full)} aria-pressed={full} title={full ? 'Exit full screen (Esc)' : 'Full screen'}>
        <Icon name={full ? 'shrink' : 'expand'} size={14} /><span class="sr-only">{full ? 'Exit full screen' : 'Full screen'}</span>
      </button>
    </div>
    <div class="flex flex-wrap items-center justify-between gap-2">
      <SeverityChips bind:value={prefs.tailSev} label="Live tail severities" />
      <p class="m-0 truncate text-[12.5px]" aria-live="polite">
        {#if paused}
          <span class="text-[var(--sev-warn)]">Paused{heldCount ? `: ${num(heldCount)} new line${heldCount === 1 ? '' : 's'} waiting` : ''}. Still receiving.</span>
        {:else if sampled}
          <span class="text-[var(--sev-warn)]">{num(sampled.rate)} msg/s, showing a sample</span>
        {:else if conn === 'error' || conn === 'closed'}
          <span class="text-[var(--sev-err)]">Connection lost. Reconnecting…</span>
        {/if}
      </p>
    </div>
  </div>

  <!-- Focusable so keyboard users can scroll the log (scrollable regions must be reachable). -->
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <div
    bind:this={scroller}
    class="logview min-h-0 grow overflow-auto px-[18px] pt-1.5 pb-3"
    class:nowrap={!prefs.wrap}
    style:--hostw="{hostCh}ch"
    role="log"
    aria-label="Log lines"
    tabindex="0"
  >
    {#if !rows.length}
      <p class="m-0 py-6 text-center font-sans text-log-dim">
        {noLevels ? 'No levels selected. Pick some above.' : conn === 'connecting' ? 'Connecting…' : paused ? 'Paused.' : 'Waiting for messages…'}
      </p>
    {/if}
    {#each rows as r (r.k)}
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="logline" title={tip(r.raw)} oncontextmenu={(e) => { e.preventDefault(); openMenu(r.device_id, e.clientX, e.clientY); }}>
        <span class="c t" title={r.received}>{clock(r.received, prefs.utc)}</span><span class="c h" title={r.device_id}>{deviceName(r.device_id)}</span><span
          class="c s {sevClass(r.severity)}">{sevLabel(r.severity)}</span
        ><span class="m">{#if showRaw}<span class="text-log-dim"><LogText text={r.pri + r.header} raw /></span>{/if}<LogText text={r.body} raw={showRaw} /><Marks line={r} /></span>
      </div>
    {/each}
  </div>
</section>

<style>
  .tail {
    border-radius: 22px;
  }
  .tail.full {
    position: fixed;
    inset: 0;
    z-index: 60;
    border-radius: 0;
    height: 100vh;
  }
  .bar {
    background: var(--log-bar);
  }
  .tail-btn {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 4px 10px;
    border-radius: 999px;
    border: 1px solid rgba(255, 255, 255, 0.18);
    background: transparent;
    color: var(--log-fg);
    cursor: pointer;
    font-size: 13px;
    text-decoration: none;
  }
  .tail-btn:hover,
  .tail-btn[aria-pressed='true'] {
    background: rgba(255, 255, 255, 0.12);
  }
  @media (max-width: 640px) {
    :global(.logline > .c.s) {
      display: none;
    }
  }
</style>

<script lang="ts">
  // The incident bundle's moment and window (SPEC §11.3): the time, typed in local time or UTC
  // (the request is always UTC), and the time before and after it, from a preset or typed. The
  // readout under it is the window the bundle will hold, cut at now.
  import {
    BUNDLE_PRESETS,
    bundleWindow,
    formatDuration,
    humanDuration,
    momentFromParts,
    momentParts,
    parseDuration,
    presetIndex,
    rfc3339,
    sideError,
    type BundleForm,
  } from '../lib/bundle';
  import { stamp } from '../lib/format';
  import { prefs } from '../lib/prefs.svelte';
  import { live } from '../lib/status.svelte';

  let { value = $bindable(), idp = 'bw' }: { value: BundleForm; /** Prefix for element ids, so two on a page don't clash. */ idp?: string } = $props();

  // ----- the moment -----
  const parts = $derived(momentParts(value.at, prefs.utc));
  function setPart(field: 'date' | 'time', v: string) {
    const next = { ...parts, [field]: v };
    const iso = momentFromParts(next.date, next.time, prefs.utc);
    if (iso) value.at = iso;
  }
  const setNow = () => (value.at = rfc3339(Math.floor(Date.now() / 1000) * 1000));

  // ----- the sides: a preset, or typed (kept as typed while it doesn't parse) -----
  let custom = $state(false);
  const preset = $derived(presetIndex(value.before, value.after));
  const isCustom = $derived(custom || preset < 0);
  let bText = $state('');
  let aText = $state('');
  // Follow changes made elsewhere (a preset, the histogram) without rewriting what's being typed.
  $effect(() => {
    if (parseDuration(bText) !== parseDuration(value.before) || !bText) bText = value.before;
    if (parseDuration(aText) !== parseDuration(value.after) || !aText) aText = value.after;
  });
  function typed(which: 'before' | 'after', text: string) {
    if (which === 'before') bText = text;
    else aText = text;
    const ms = parseDuration(text);
    value[which] = Number.isFinite(ms) ? formatDuration(ms) : text;
  }
  const bErr = $derived(isCustom ? sideError('Before', bText) : '');
  const aErr = $derived(isCustom ? sideError('After', aText) : '');

  // The readout: the window as of now (the clock ticks each second, so "cut at now" stays true).
  const win = $derived(bundleWindow(value.at, value.before, value.after, live.now));
  const span = $derived(typeof win === 'string' ? 0 : Date.parse(win.to) - Date.parse(win.from));
</script>

{#snippet zone()}
  <div class="seg" role="radiogroup" aria-label="Type the time in">
    <button type="button" role="radio" aria-checked={!prefs.utc} onclick={() => (prefs.utc = false)}>Local</button>
    <button type="button" role="radio" aria-checked={prefs.utc} onclick={() => (prefs.utc = true)}>UTC</button>
  </div>
{/snippet}

<div class="bw" role="group" aria-label="The moment and the window around it">
  <div class="line">
    <span class="lab" id="{idp}-at">Around</span>
    <div class="ctl">
      <input class="in" type="date" aria-labelledby="{idp}-at" value={parts.date} onchange={(e) => setPart('date', e.currentTarget.value)} />
      <input class="in" type="time" step="1" aria-label="Time of the moment" value={parts.time} onchange={(e) => setPart('time', e.currentTarget.value)} />
      {@render zone()}
      <button type="button" class="ghost-btn now" onclick={setNow} title="The moment is now: the window is the time before it">Now</button>
    </div>
  </div>
  <div class="line">
    <span class="lab" id="{idp}-win">Before / after</span>
    <div class="ctl">
    <div class="seg wrap" role="radiogroup" aria-labelledby="{idp}-win">
      {#each BUNDLE_PRESETS as p, i (p.label)}
        <button
          type="button"
          role="radio"
          aria-checked={!isCustom && preset === i}
          onclick={() => {
            custom = false;
            value.before = p.before;
            value.after = p.after;
          }}>{p.label}</button
        >
      {/each}
      <button type="button" role="radio" aria-checked={isCustom} onclick={() => (custom = true)}>Custom</button>
    </div>
    </div>
  </div>
  {#if isCustom}
    <div class="line sides">
      <span class="lab"></span>
      <div class="ctl">
      <label class="side">
        <span>Before</span>
        <input class="in dur" value={bText} oninput={(e) => typed('before', e.currentTarget.value)} placeholder="30m" spellcheck="false" aria-invalid={!!bErr} title="A duration such as 30m, 1h30m or 2d (at most 7d)" />
      </label>
      <label class="side">
        <span>After</span>
        <input class="in dur" value={aText} oninput={(e) => typed('after', e.currentTarget.value)} placeholder="10m" spellcheck="false" aria-invalid={!!aErr} title="A duration such as 10m, 1h or 0s (at most 7d)" />
      </label>
      </div>
    </div>
  {/if}
  <p class="readout" aria-live="polite">
    {#if bErr || aErr}
      <span class="err" role="alert">{bErr || aErr}</span>
    {:else if typeof win === 'string'}
      <span class="err" role="alert">{win}</span>
    {:else}
      Window <b class="font-mono">{stamp(win.from, prefs.utc).slice(0, 14)}</b> → <b class="font-mono">{stamp(win.to, prefs.utc).slice(0, 14)}</b>{prefs.utc ? ' UTC' : ''}
      · {humanDuration(Math.round(span / 1000) * 1000)}{#if win.cut}{' '}<span class="cut" title="The window would end after now, so it ends now (the server does the same)">· cut at now</span>{/if}
    {/if}
  </p>
</div>

<style>
  .bw {
    display: flex;
    flex-direction: column;
    gap: 8px;
    min-width: 0;
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 10px;
  }
  .ctl {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 10px;
    flex: 1 1 0;
    min-width: 14rem;
  }
  .lab {
    flex: none;
    width: var(--blab, 104px);
    font-size: 13px;
    font-weight: 600;
  }
  .seg {
    display: inline-flex;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 3px;
  }
  .seg.wrap {
    flex-wrap: wrap;
    border-radius: 18px;
  }
  .seg button {
    height: 28px;
    border: 0;
    background: transparent;
    color: var(--fg);
    padding: 0 12px;
    border-radius: 999px;
    font-size: 13px;
    cursor: pointer;
    white-space: nowrap;
  }
  .seg button[aria-checked='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
  .in {
    height: 36px;
    padding: 0 10px;
    border-radius: 12px;
    border: 1px solid var(--input-border);
    background: var(--input);
    color: var(--fg);
    font: inherit;
    font-size: 13.5px;
    font-variant-numeric: tabular-nums;
  }
  .in[aria-invalid='true'] {
    border-color: var(--bad);
  }
  :global(.dark) .in {
    color-scheme: dark;
  }
  .dur {
    width: 8.5em;
    font-family: var(--font-mono);
  }
  .side {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 13px;
    font-weight: 600;
  }
  .now {
    padding: 7px 14px;
  }
  .readout {
    margin: 0;
    padding-left: calc(var(--blab, 104px) + 10px);
    font-size: 13.5px;
  }
  .cut {
    color: var(--muted);
  }
  .err {
    color: var(--bad-fg);
    font-weight: 500;
  }
</style>

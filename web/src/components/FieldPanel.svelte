<script lang="ts">
  // The field panel (SPEC §10.1.1): each field's top values and their exact counts for the
  // current query, over the span the summary has counted so far. The fields come from
  // /api/search/schema; this component has no field list of its own.
  //
  // A click on a value adds it as a filter (values of one field OR together, fields AND);
  // Alt/Option-click or "−" excludes it; "+" adds it, for touch and keyboard. "(none)" and
  // "N others" rows can't be clicked. Clicking a value twice does the same thing twice.
  import type { FieldDescriptor, SummaryResponse } from '../lib/api';
  import { countedLine, type Chip } from '../lib/events';
  import { num } from '../lib/format';

  let {
    fields,
    summary,
    status,
    error = '',
    utc = false,
    chips = [],
    state: stateOf,
    onpick,
    oncontinue,
    unit = 'line',
    spanText = '',
    valueExtra,
  }: {
    fields: FieldDescriptor[];
    summary: SummaryResponse | null;
    status: 'idle' | 'running' | 'paused' | 'done' | 'error';
    error?: string;
    utc?: boolean;
    chips?: Chip[];
    /** Whether a value is already filtered in ("in"), out ("out"), or neither (""). */
    state: (f: FieldDescriptor, value: string) => 'in' | 'out' | '';
    onpick: (f: FieldDescriptor, value: string, exclude: boolean) => void;
    oncontinue: () => void;
    /** What a count counts ("line"; 2.0's Flows tab: "flow"). */
    unit?: string;
    /** Replaces the counted-span line (flows report progress instead of counted_from). */
    spanText?: string;
    /** Text after a value's count (flows: its bytes). */
    valueExtra?: (v: import('../lib/api').FieldValueCount) => string;
  } = $props();

  const byKey = $derived(new Map((summary?.fields ?? []).map((f) => [f.key, f])));
  const pct = (n: number) => (summary && summary.matched ? Math.max(1.5, (n / summary.matched) * 100) : 0);

  function click(e: MouseEvent, f: FieldDescriptor, value: string) {
    onpick(f, value, e.altKey);
  }
</script>

<aside class="fp log-panel" aria-label="Field values">
  <div class="fbar">
    <b class="text-white">Fields</b>
    {#if summary}<span class="matched">{num(summary.matched)} {unit}{summary.matched === 1 ? '' : 's'}</span>{/if}
  </div>
  <div class="span" aria-live="polite">
    {#if error}<span class="err" role="alert">{error}</span>
    {:else if summary}
      <span>{spanText || `${countedLine(summary.from, summary.to, summary.counted_from, utc)}${utc ? ' UTC' : ''}`}</span>
      {#if status === 'running'}<span class="busy"><span class="spin" aria-hidden="true"></span>Counting…</span>{/if}
    {:else if status === 'running'}<span class="busy"><span class="spin" aria-hidden="true"></span>Counting…</span>{/if}
    {#if status === 'paused'}
      <p class="paused">Counting stopped after 60 s of scanning. The counts are exact for the span above.</p>
      <button type="button" class="tail-btn" onclick={oncontinue}>Count the rest</button>
    {/if}
  </div>
  {#if chips.length}
    <div class="chips" aria-label="Active filters">
      {#each chips as c (c.key)}
        <button type="button" class="chip" class:out={c.excluded} title="{c.title} (click to remove)" onclick={c.remove}>
          {c.text}<span aria-hidden="true" class="x">×</span>
        </button>
      {/each}
    </div>
  {/if}
  <div class="flist">
    {#each fields as f (f.key)}
      {@const s = byKey.get(f.key)}
      <section class="fsec" aria-labelledby="fp-{f.key}">
        <h3 id="fp-{f.key}">
          {f.label}
          {#if s}<span class="distinct">{num(s.distinct)}{s.distinct_capped ? '+' : ''} value{s.distinct === 1 ? '' : 's'}</span>{/if}
        </h3>
        {#if !s}
          <p class="dim">{status === 'running' ? '…' : '–'}</p>
        {:else}
          {#if !s.values.length && !s.none}<p class="dim">No values yet.</p>{/if}
          <ul>
            {#each s.values as v (v.value)}
              {@const st = stateOf(f, v.value)}
              <li class="row" class:in={st === 'in'} class:out={st === 'out'}>
                <span class="meter" style:width="{pct(v.count)}%" aria-hidden="true"></span>
                {#if v.filterable}
                  <button
                    type="button"
                    class="val"
                    title="Show only {v.label} (Alt-click: leave it out)"
                    onclick={(e) => click(e, f, v.value)}>{v.label}</button
                  >
                {:else}
                  <span class="val nf" title="This value can't be used as a filter">{v.label}</span>
                {/if}
                <span class="cnt">{num(v.count)}</span>
                {#if valueExtra}<span class="xtra">{valueExtra(v)}</span>{/if}
                {#if v.filterable}
                  <button type="button" class="pm" aria-label="Show only {v.label}" title="Show only {v.label}" onclick={() => onpick(f, v.value, false)}>+</button>
                  <button type="button" class="pm" aria-label="Leave out {v.label}" title="Leave out {v.label}" onclick={() => onpick(f, v.value, true)}>−</button>
                {/if}
              </li>
            {/each}
            {#if s.other > 0}
              <li class="row static"><span class="val dim">{num(s.values.length ? s.distinct - s.values.length : s.distinct)} others</span><span class="cnt">{num(s.other)}</span></li>
            {/if}
            {#if s.none > 0}
              <li class="row static" title="Lines with no {f.label.toLowerCase()} in the header; no filter can pick them yet">
                <span class="val dim">(none)</span><span class="cnt">{num(s.none)}</span>
              </li>
            {/if}
          </ul>
        {/if}
      </section>
    {/each}
  </div>
</aside>

<style>
  .fp {
    border-radius: 22px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    font-family: var(--font-sans);
    font-size: 13px;
    color: var(--log-fg);
  }
  .fbar {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 16px;
    background: var(--log-bar);
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
  }
  .xtra {
    position: relative;
    flex: none;
    min-width: 5.2em;
    text-align: right;
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--log-dim);
  }
  .matched {
    margin-left: auto;
    font-family: var(--font-mono);
    color: var(--log-fg);
  }
  .span {
    padding: 8px 16px 4px;
    color: var(--log-dim);
    font-size: 12.5px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    align-items: flex-start;
  }
  .paused {
    margin: 0;
    color: var(--sev-warn);
  }
  .err {
    color: var(--sev-err);
  }
  .busy {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--sev-warn);
  }
  .spin {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    border: 2px solid rgba(255, 255, 255, 0.2);
    border-top-color: var(--sev-warn);
    animation: spin 0.9s linear infinite;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 5px;
    padding: 6px 16px 2px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    max-width: 100%;
    padding: 2px 8px;
    border-radius: 999px;
    border: 1px solid rgba(157, 188, 255, 0.5);
    background: rgba(157, 188, 255, 0.14);
    color: var(--log-fg);
    font-size: 12.5px;
    font-family: var(--font-mono);
    cursor: pointer;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .chip.out {
    border-color: rgba(255, 138, 142, 0.55);
    background: rgba(255, 138, 142, 0.12);
  }
  .chip .x {
    color: var(--log-dim);
  }
  .flist {
    padding: 4px 8px 12px;
    overflow: auto;
  }
  .fsec {
    padding: 6px 8px 4px;
  }
  h3 {
    display: flex;
    align-items: baseline;
    gap: 8px;
    margin: 4px 0 4px;
    font-size: 12.5px;
    font-weight: 700;
    color: var(--log-fg);
  }
  .distinct {
    font-weight: 400;
    color: var(--log-dim);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .row {
    position: relative;
    display: flex;
    align-items: center;
    gap: 4px;
    padding: 1px 2px 1px 6px;
    border-radius: 6px;
  }
  .row:hover:not(.static) {
    background: rgba(255, 255, 255, 0.06);
  }
  .row.in {
    box-shadow: inset 2px 0 0 var(--log-host);
  }
  .row.out .val {
    text-decoration: line-through;
    color: var(--log-dim);
  }
  .meter {
    position: absolute;
    left: 0;
    top: 2px;
    bottom: 2px;
    border-radius: 5px;
    background: rgba(157, 188, 255, 0.12);
    pointer-events: none;
  }
  .val {
    position: relative;
    flex: 1 1 auto;
    min-width: 0;
    padding: 2px 0;
    border: 0;
    background: transparent;
    color: var(--log-fg);
    font: inherit;
    font-family: var(--font-mono);
    font-size: 12.5px;
    text-align: left;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: pointer;
  }
  .val.nf,
  .static .val {
    cursor: default;
  }
  .val:hover:not(.nf) {
    text-decoration: underline;
  }
  .cnt {
    position: relative;
    font-family: var(--font-mono);
    font-size: 12.5px;
    color: var(--log-fg);
    font-variant-numeric: tabular-nums;
  }
  .pm {
    position: relative;
    width: 20px;
    height: 20px;
    padding: 0;
    border-radius: 6px;
    border: 1px solid transparent;
    background: transparent;
    color: var(--log-dim);
    font-size: 14px;
    line-height: 1;
    cursor: pointer;
  }
  .row:hover .pm,
  .pm:focus-visible {
    border-color: rgba(255, 255, 255, 0.18);
    color: var(--log-fg);
  }
  .dim {
    color: var(--log-dim);
    margin: 0;
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
  }
  .tail-btn:hover {
    background: rgba(255, 255, 255, 0.12);
  }
</style>

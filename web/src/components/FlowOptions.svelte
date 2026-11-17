<script lang="ts">
  // Flows in an export or a bundle (SPEC §13.4, §13.11 #6): Leave flows out, offered before
  // building and pre-selected for a window over 4 h whose flows are estimated above 1 GB (the user
  // can clear it), and which flow files the zip holds (the CSV and the IPFIX file, both by default).
  // `leave` is null until the user picks, and then follows `auto`.
  import { dbytes, short, type FlowFormat } from '../lib/flows';

  let {
    leave = $bindable(null),
    formats = $bindable(['csv', 'ipfix']),
    auto,
    flow,
    tooMany = '',
    idp = 'fl',
    fixed = false,
  }: {
    leave?: boolean | null;
    formats?: FlowFormat[];
    /** The pre-selection rule's answer for this window and estimate. */
    auto: boolean;
    /** The window's flows, from the estimate (null before it's in). */
    flow: { records: number; bytes: number } | null;
    /** The server's "Too many flow records" message, when flows can't go in this zip. */
    tooMany?: string;
    idp?: string;
    /** A flows-only export: no Leave flows out, just the files. */
    fixed?: boolean;
  } = $props();

  const on = $derived(leave ?? auto);
  function toggle(f: FlowFormat, v: boolean) {
    const next = v ? [...new Set([...formats, f])] : formats.filter((x) => x !== f);
    if (next.length) formats = (['csv', 'ipfix'] as FlowFormat[]).filter((x) => next.includes(x));
  }
</script>

<div class="fo" data-flow-options>
  {#if !fixed}
  <label class="flex items-center gap-2 text-[14px]">
    <input id="leave-flows" type="checkbox" checked={on} onchange={(e) => (leave = (e.currentTarget as HTMLInputElement).checked)} />
    <b>Leave flows out</b>
    {#if flow}<span class="text-muted">{on ? 'leaves out' : 'flows add'} {short(flow.records)} records, about {dbytes(flow.bytes)}</span>{/if}
  </label>
  {#if on && leave === null && auto && tooMany}
    <p class="note">Pre-selected: this window's flows don't fit in one zip. {tooMany}</p>
  {:else if on && leave === null && auto}
    <p class="note">Pre-selected: the window is over 4 hours and its flows are estimated above 1 GB. Clear it to include them.</p>
  {:else if !on && tooMany}
    <p class="note bad" role="alert">{tooMany} Or leave flows out.</p>
  {/if}
  {:else if flow}
    <span class="text-[14px] text-muted">{short(flow.records)} records, about {dbytes(flow.bytes)}</span>
  {/if}
  {#if !on}
    <div class="flex flex-wrap items-center gap-3 text-[14px]" role="group" aria-label="Flow files">
      <span class="text-muted">Flows as</span>
      <label class="flex items-center gap-1.5" title="One row per record: what a person opens first (a spreadsheet, grep)">
        <input id="{idp}-csv" type="checkbox" checked={formats.includes('csv')} disabled={formats.length === 1 && formats[0] === 'csv'} onchange={(e) => toggle('csv', (e.currentTarget as HTMLInputElement).checked)} />
        CSV
      </label>
      <label class="flex items-center gap-1.5" title="The lossless form flow tools read (RFC 5655), enterprise fields included">
        <input id="{idp}-ipfix" type="checkbox" checked={formats.includes('ipfix')} disabled={formats.length === 1 && formats[0] === 'ipfix'} onchange={(e) => toggle('ipfix', (e.currentTarget as HTMLInputElement).checked)} />
        IPFIX file
      </label>
    </div>
  {/if}
</div>

<style>
  .fo {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 10px 14px;
    border-radius: 14px;
    border: 1px solid var(--border);
  }
  .note {
    margin: 0;
    font-size: 13px;
    color: var(--muted);
  }
  .note.bad {
    color: var(--bad-fg);
    font-weight: 500;
  }
</style>

<script lang="ts">
  // The bundle's data types: every type with data in the window (types: [], the default), or one.
  import type { DataType } from '../lib/api';

  let { value = $bindable(), types, label = 'Data types' }: { value: string[]; types: DataType[]; label?: string } = $props();
</script>

<div class="seg" role="radiogroup" aria-label={label}>
  <button type="button" role="radio" aria-checked={!value.length} onclick={() => (value = [])} title="Each type that has anything stored in the window gets its own folder">
    Every type with data
  </button>
  {#each types as t (t.type)}
    <button type="button" role="radio" aria-checked={value.length === 1 && value[0] === t.type} onclick={() => (value = [t.type])}>{t.label}</button>
  {/each}
</div>

<style>
  .seg {
    display: inline-flex;
    flex-wrap: wrap;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 3px;
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
</style>

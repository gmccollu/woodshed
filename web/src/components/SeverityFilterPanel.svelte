<script lang="ts">
  // The device page's severity filter (2.1, SPEC §13.10 decision 86): what this device's syslog
  // stores, its own setting or the default from Settings, and what was left out in the last
  // 24 h. Left-out messages aren't stored (search, the live tail and exports don't have them);
  // they're counted, and that's a choice, never a drop, so nothing here is coloured as an error.
  import { ApiError, getSettings, patchDevice, type Device, type SeverityName } from '../lib/api';
  import { num } from '../lib/format';
  import { countsText, FILTER_LEVELS, filterChoice, filterPhrase, severityPatch } from '../lib/severity';
  import { replaceDevice } from '../lib/status.svelte';

  let { device, onchange }: { device: Device; onchange?: (d: Device) => void } = $props();

  /**
   * The default: what's in effect for the device while it follows it, otherwise read from
   * /api/settings once (the device only says what's in effect for it).
   */
  let settingsDefault = $state('');
  /** Bumped when the page regains focus: Settings may have changed the default in another tab. */
  let focused = $state(0);
  const defaultLevel = $derived(device.min_severity === 'default' ? (device.min_severity_effective ?? '') : settingsDefault);
  $effect(() => {
    void focused;
    if (device.min_severity === 'default') return;
    getSettings().then(
      (s) => (settingsDefault = s.settings.syslog?.min_severity ?? 'debug'),
      () => {},
    );
  });

  const own = $derived(!!device.min_severity && device.min_severity !== 'default');
  const effective = $derived(device.min_severity_effective ?? 'debug');
  const filtered = $derived(device.filtered_24h ?? 0);
  const by = $derived(device.filtered_by_severity_24h ?? {});
  const sevs = $derived(Object.keys(by).filter((k) => by[k] > 0));
  const choice = $derived(own ? (device.min_severity as string) : 'default');

  let saving = $state(false);
  let error = $state('');
  let select = $state<HTMLSelectElement>();
  async function save(v: string) {
    saving = true;
    error = '';
    try {
      const d = await patchDevice(device.id, severityPatch(v as SeverityName | 'default'));
      replaceDevice(d);
      onchange?.(d);
    } catch (e) {
      error = e instanceof ApiError && e.fields.min_severity ? e.fields.min_severity : (e as Error).message;
      // Not saved: show the setting in effect again, not the one picked.
      if (select) select.value = choice;
    } finally {
      saving = false;
    }
  }
</script>

<svelte:window onfocus={() => focused++} />

<section class="card" aria-labelledby="sevf-h">
  <h2 id="sevf-h" class="m-0 text-[17px] font-bold">Syslog stored</h2>
  <p class="mt-1 mb-0 text-[13.5px]">
    Stores <strong>{filterPhrase(effective)}</strong>
    <span class="text-muted">{own ? "(this device's own setting)" : '(the default, from Settings)'}</span>.
    {#if filtered > 0}
      {#if sevs.length === 1}
        <span class="block" data-testid="sevf-left-out">{sevs[0][0].toUpperCase() + sevs[0].slice(1)} not stored: {num(filtered)} in the last 24 h.</span>
      {:else}
        <span class="block" data-testid="sevf-left-out">Not stored in the last 24 h: {countsText(by, num)}.</span>
      {/if}
    {:else if effective !== 'debug'}
      <span class="block text-muted">Nothing left out in the last 24 h.</span>
    {/if}
  </p>
  <label class="mt-3 flex flex-wrap items-center gap-2 text-[13.5px]">
    <span>Store from</span>
    <select class="field w-auto" bind:this={select} value={choice} disabled={saving} onchange={(e) => save((e.currentTarget as HTMLSelectElement).value)}>
      <option value="default">The default{defaultLevel ? ` (${filterPhrase(defaultLevel)})` : ''}</option>
      {#each FILTER_LEVELS as l (l)}<option value={l}>{filterChoice(l)}</option>{/each}
    </select>
  </label>
  {#if error}<p class="mb-0 text-bad-fg" role="alert">{error}</p>{/if}
  <p class="hint mb-0">
    A severity stores that severity and more severe ones, from the next message (what's stored stays). What's left out isn't stored
    anywhere, so search, the live tail and exports don't have it; it's counted here and in bundles. Messages without a severity are
    always stored, and SNMP traps, polls and flows aren't affected.
  </p>
</section>

<style>
  .hint {
    font-size: 13px;
    color: var(--muted);
    margin-top: 8px;
  }
</style>

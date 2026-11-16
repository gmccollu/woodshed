<script lang="ts">
  // Devices → Polled: every poll target (docs/api.md → Poll targets), including addresses that
  // haven't answered yet and so aren't devices yet. Edit opens the form; the name opens the
  // device page with its Polling panel.
  import { getPollTargets } from '../lib/api';
  import { ago, dateTime, num } from '../lib/format';
  import { statusLabel, type PollTarget } from '../lib/poll';
  import { deviceName, live } from '../lib/status.svelte';

  let { version = 0, onedit, onadd }: { version?: number; onedit: (t: PollTarget) => void; onadd: () => void } = $props();

  let rows = $state<PollTarget[] | null>(null);
  let loadError = $state('');
  $effect(() => {
    void version;
    let stop = false;
    const load = () =>
      getPollTargets().then(
        (t) => {
          if (!stop) (rows = t), (loadError = '');
        },
        (e) => {
          if (!stop) loadError = (e as Error).message;
        },
      );
    load();
    const t = setInterval(load, 10_000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  });
  const iv = (s: number) => (s >= 60 ? `${s / 60} min` : `${s} s`);
</script>

<div class="overflow-x-auto">
  <table class="w-full border-collapse text-[14px]">
    <thead>
      <tr>
        <th scope="col">Status</th>
        <th scope="col">Device</th>
        <th scope="col">Polled at</th>
        <th scope="col">Version</th>
        <th scope="col">Every</th>
        <th scope="col">Last answer</th>
        <th scope="col" class="text-right">Interfaces</th>
        <th scope="col"><span class="sr-only">Actions</span></th>
      </tr>
    </thead>
    <tbody>
      {#if loadError}
        <tr><td colspan="8" class="text-bad-fg">Couldn't load the poll targets: {loadError}</td></tr>
      {:else if rows === null}
        <tr><td colspan="8" class="text-muted">Loading…</td></tr>
      {:else if !rows.length}
        <tr>
          <td colspan="8" class="text-muted">
            No devices are polled. Woodshed sends no SNMP requests until you add one.
            <button class="linkbtn" onclick={onadd}>Add polling by address</button>
          </td>
        </tr>
      {/if}
      {#each rows ?? [] as t (t.id)}
        <tr>
          <td><span class="chip {t.state.status}" title={t.state.error || statusLabel(t.state.status)}>{statusLabel(t.state.status)}</span></td>
          <td>
            <a class="text-link underline" href="#/device?id={encodeURIComponent(t.device_id)}">{t.state.sys_name || deviceName(t.device_id)}</a>
            {#if t.state.status === 'pending'}<span class="sub">becomes a device on its first answer</span>{/if}
          </td>
          <td class="font-mono text-[13px] whitespace-nowrap">{t.address}{t.port !== 161 ? `:${t.port}` : ''}{#if t.device_id !== t.address}<span class="sub font-sans">stored under {t.device_id}</span>{/if}</td>
          <td>v{t.version}{#if t.version === '3'}<span class="sub">{t.v3_user}</span>{/if}</td>
          <td class="whitespace-nowrap">{iv(t.interval_s)}{#if t.state.backoff_s}<span class="sub">backing off: {iv(t.state.backoff_s)}</span>{/if}</td>
          <td class="whitespace-nowrap">
            {#if t.state.last_ok}<span title={dateTime(t.state.last_ok)}>{ago(t.state.last_ok, live.now)}</span>{:else}<span class="text-muted">never</span>{/if}
            {#if t.state.failing_since}<span class="sub">not answering since {ago(t.state.failing_since, live.now)}</span>{/if}
          </td>
          <td class="text-right tabular-nums whitespace-nowrap">
            {#if t.presets.includes('interfaces') && t.state.interfaces_total}
              {num(t.state.interfaces_polled)}{t.state.interfaces_total > t.state.interfaces_polled ? ` of ${num(t.state.interfaces_total)}` : ''}
              {#if !t.state.hc_counters}<span class="sub">32-bit counters</span>{/if}
            {:else}–{/if}
          </td>
          <td class="text-right"><button class="ghost-btn" onclick={() => onedit(t)} aria-label="Edit polling of {t.address}">Edit</button></td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  th {
    text-align: left;
    font-size: 12.5px;
    font-weight: 600;
    color: var(--muted);
    padding: 8px 10px;
    border-bottom: 1px solid var(--divider);
    white-space: nowrap;
  }
  th.text-right {
    text-align: right;
  }
  td {
    padding: 9px 10px;
    border-bottom: 1px solid var(--divider);
    vertical-align: middle;
  }
  tr:last-child td {
    border-bottom: 0;
  }
  th:first-child,
  td:first-child {
    padding-left: 20px;
  }
  th:last-child,
  td:last-child {
    padding-right: 16px;
  }
  .sub {
    display: block;
    font-size: 12px;
    color: var(--muted);
  }
  .chip {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
    border: 1px solid var(--input-border);
    background: var(--chip);
  }
  .chip.ok {
    border-color: var(--ok);
    color: var(--ok-fg);
  }
  .chip.failing {
    border-color: var(--warn);
    color: var(--warn-fg);
    background: var(--warn-bg);
  }
  .chip.backing_off {
    border-color: var(--bad);
    color: var(--bad-fg);
    background: var(--error-bg);
  }
  .linkbtn {
    background: none;
    border: 0;
    padding: 0;
    font: inherit;
    color: var(--link);
    text-decoration: underline;
    cursor: pointer;
  }
</style>

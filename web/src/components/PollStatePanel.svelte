<script lang="ts">
  // Settings → Polling: the poller's last hour (GET /api/poll): how many devices answer, cycles,
  // failures by status, overruns and unmatched responses.
  import { getPollState } from '../lib/api';
  import { ago, dateTime, num } from '../lib/format';
  import { FAILURE_LABEL, type PollState } from '../lib/poll';
  import { live } from '../lib/status.svelte';

  let st = $state<PollState | null>(null);
  let loadError = $state('');
  $effect(() => {
    const load = () =>
      getPollState().then(
        (s) => ((st = s), (loadError = '')),
        (e) => (loadError = (e as Error).message),
      );
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  });
  const failures = $derived(Object.entries(st?.hour.failures ?? {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]));
  const failed = $derived(failures.reduce((n, [, c]) => n + c, 0));
</script>

<div class="state" aria-live="polite">
  <h3 class="m-0 text-[14px] font-semibold">Last hour</h3>
  {#if loadError}
    <p class="m-0 text-[13px] text-bad-fg">Couldn't read the poller's state: {loadError}</p>
  {:else if !st}
    <p class="m-0 text-[13px] text-muted">Loading…</p>
  {:else if !st.targets}
    <p class="m-0 text-[13px] text-muted">No devices are polled, so no SNMP requests are sent.</p>
  {:else}
    <dl>
      <div><dt>Polled devices</dt><dd>{num(st.targets)}: {num(st.answering)} answering{st.failing ? `, ${num(st.failing)} not answering` : ''}{st.backing_off ? `, ${num(st.backing_off)} backing off` : ''}</dd></div>
      <div><dt>Last cycle</dt><dd>{#if st.last_cycle}<span title={dateTime(st.last_cycle)}>{ago(st.last_cycle, live.now)}</span>{:else}none yet{/if}</dd></div>
      <div><dt>Cycles</dt><dd class="tabular-nums">{num(st.hour.cycles)}</dd></div>
      <div>
        <dt>Failed cycles</dt>
        <dd class="tabular-nums">
          {num(failed)}{#if failures.length}: {failures.map(([k, n]) => `${FAILURE_LABEL[k] ?? k} ${num(n)}`).join(', ')}{/if}
        </dd>
      </div>
      <div><dt>Skipped (overruns)</dt><dd class="tabular-nums" class:text-warn-fg={st.hour.overruns > 0}>{num(st.hour.overruns)}</dd></div>
      <div><dt>Unmatched replies</dt><dd class="tabular-nums" title="Responses from another address or with an unknown request ID; they're dropped">{num(st.hour.unmatched)}</dd></div>
    </dl>
  {/if}
</div>

<style>
  .state {
    padding: 12px 14px;
    border-radius: 14px;
    border: 1px solid var(--divider);
  }
  dl {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 28px;
    margin: 8px 0 0;
    font-size: 14px;
  }
  dt {
    font-size: 12px;
    color: var(--muted);
  }
  dd {
    margin: 0;
  }
</style>

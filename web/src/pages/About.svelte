<script lang="ts">
  import { getStats, type Stats } from '../lib/api';
  import { bytes, dateTime, duration, num } from '../lib/format';
  import { live } from '../lib/status.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import QueueChart from '../components/QueueChart.svelte';

  // The UDP queue and the drop reasons come from /api/stats.
  let stats = $state<Stats | null>(null);
  $effect(() => {
    const load = () =>
      getStats()
        .then((s) => (stats = s))
        .catch(() => {});
    load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  });
  const reasons = $derived(stats?.dropped_by_reason);
  const anyReason = $derived(!!reasons && reasons.paused + reasons.write_error + reasons.refused + reasons.queue_full > 0);
  const queueName = (l: string) => (l === 'udp' ? 'Syslog over UDP' : l === 'snmp' ? 'SNMP traps' : l.toUpperCase());
  const pct = (a: number, b: number) => (b > 0 ? Math.min(100, Math.round((a / b) * 100)) : 0);

  const st = $derived(live.status);
  const osName = $derived(
    st?.os.startsWith('darwin') ? 'macOS' : st?.os.startsWith('windows') ? 'Windows' : st?.os.startsWith('linux') ? 'Linux' : (st?.os ?? ''),
  );
  const shortBuf = $derived(!!st && st.udp_rcvbuf_bytes < st.udp_rcvbuf_requested_bytes);
  const bufHint = $derived(
    st?.os.startsWith('linux')
      ? 'The kernel caps it at net.core.rmem_max. The deb and rpm packages raise that to 32 MiB; if you installed from the tarball, set it yourself in /etc/sysctl.d/.'
      : st?.os.startsWith('darwin')
        ? 'macOS caps socket buffers with the kern.ipc.maxsockbuf sysctl.'
        : 'The OS gave a smaller buffer than requested.',
  );
</script>

<div class="mx-auto max-w-3xl space-y-4">
  <section class="card">
    <h1 class="m-0 text-xl font-bold tracking-tight">About Woodshed</h1>
    {#if !st}
      <p class="text-muted">Loading…</p>
    {:else}
      <dl class="mt-4 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-3 text-[14.5px]">
        <dt>Version</dt>
        <dd><b>{st.version}</b> <span class="text-muted">(build {st.build})</span></dd>
        <dt>Running on</dt>
        <dd>{osName} <span class="text-muted">({st.os})</span></dd>
        <dt>Started</dt>
        <dd>{dateTime(st.started_at)} <span class="text-muted">· up {duration(st.started_at, live.now)}</span></dd>
        <dt>Data folder</dt>
        <dd class="flex flex-wrap items-center gap-2">
          <code class="font-mono text-[13.5px] break-all">{st.data_dir}</code>
          <CopyButton text={st.data_dir} />
        </dd>
        <dt>UDP receive buffer</dt>
        <dd>
          <b>{bytes(st.udp_rcvbuf_bytes)}</b>
          <span class="text-muted">(asked for {bytes(st.udp_rcvbuf_requested_bytes)})</span>
          {#if shortBuf}
            <p class="mt-1 mb-0 text-[13px] text-warn-fg">Smaller than requested, so a burst is more likely to overflow it. {bufHint}</p>
          {/if}
        </dd>
        <dt>Releases</dt>
        <dd>
          {#if st.releases_url}
            <a class="text-link underline break-all" href={st.releases_url} rel="noreferrer noopener" target="_blank">{st.releases_url}</a>
          {:else}
            <span class="text-muted">No public releases page yet.</span>
          {/if}
          <p class="mt-1 mb-0 text-[13px] text-muted">Woodshed never checks for updates or connects out; compare this version with the releases page yourself.</p>
        </dd>
      </dl>
    {/if}
  </section>

  {#if st}
    <section class="card">
      <h2 class="m-0 mb-2 text-[17px] font-bold">Dropped messages</h2>
      <p class="m-0 text-[14.5px] leading-relaxed">
        Woodshed counts every message it drops itself (when the low-disk guard pauses writing, a write fails, a new sender is over the device
        limits, or the UDP receive queue is full), and shows the count on the dashboard.
      </p>
      {#if anyReason && reasons}
        <p class="mt-2 mb-0 text-[14.5px]">
          Last 24 hours, by reason:
          {#each [['writes paused (low disk)', reasons.paused], ['write errors', reasons.write_error], ['new senders refused', reasons.refused], ['UDP queue full', reasons.queue_full]].filter(([, n]) => Number(n) > 0) as [what, n], i (what)}{i ? ' · ' : ' '}<b>{num(Number(n))}</b> {what}{/each}.
        </p>
      {/if}
      {#if st.kernel_drops_visible}
        <p class="mt-2 mb-0 text-[14.5px] leading-relaxed">
          On {osName} it also reads the kernel's UDP drop counter for its socket, so packets the OS discarded before Woodshed could read them
          (for example when the receive buffer overflows) are counted too.
        </p>
      {:else}
        <p class="mt-2 mb-0 rounded-xl border border-[var(--warn-border)] bg-[var(--warn-bg)] px-3 py-2 text-[14.5px] leading-relaxed">
          <b>{osName} doesn't tell programs how many UDP packets the kernel dropped.</b> If the receive buffer overflows during a burst, those
          messages are lost before Woodshed sees them, and no counter here can show it. A dropped count of 0 means Woodshed itself lost
          nothing; it can't prove the kernel didn't. Use TCP for senders where every message matters.
        </p>
      {/if}
    </section>

    {#each stats?.udp_queue ?? [] as q (q.listener)}
      <section class="card" aria-labelledby="queue-{q.listener}">
        <h2 id="queue-{q.listener}" class="m-0 mb-2 text-[17px] font-bold">UDP receive queue <span class="font-normal text-muted">· {queueName(q.listener)}</span></h2>
        <p class="m-0 text-[14.5px] leading-relaxed">
          UDP messages wait here while writing to disk catches up, so a slow disk doesn't make the OS drop them. It holds up to
          <b>{num(q.capacity_messages)}</b> messages or <b>{bytes(q.capacity_bytes)}</b>, whichever fills first.
        </p>
        <dl class="mt-3 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-[14.5px]">
          <dt>Waiting now</dt>
          <dd>{num(q.depth)}</dd>
          <dt>Most at once, 24 h</dt>
          <dd>{num(q.high_water_24h)} <span class="text-muted">({pct(q.high_water_24h, q.capacity_messages)}% of capacity)</span></dd>
          <dt>Dropped, queue full</dt>
          <dd class:text-bad-fg={q.dropped_24h > 0}>{num(q.dropped_24h)} <span class="text-muted">in 24 h</span></dd>
        </dl>
        {#if q.high_water_by_hour.length}
          <QueueChart values={q.high_water_by_hour} capacity={q.capacity_messages} now={live.now} />
        {/if}
        <p class="mt-3 mb-0 text-[13px] leading-relaxed text-muted">
          {#if q.dropped_24h > 0}
            When the queue fills, the disk is falling behind: check its health and what else is using it, or raise
            <code class="font-mono">listeners.udp_queue_messages</code> in the config file and restart Woodshed.
          {:else}
            If senders report messages missing while this queue never fills, they were lost before Woodshed read them: in the OS
            socket buffer or on the network.
          {/if}
        </p>
      </section>
    {/each}

    <section class="card">
      <h2 class="m-0 mb-2 text-[17px] font-bold">Listeners</h2>
      <ul class="m-0 list-none space-y-1.5 p-0 text-[14.5px]">
        {#each st.listeners as l (l.proto + l.port)}
          <li class="flex items-center gap-2">
            <span class="inline-block size-[9px] rounded-full" style:background={l.ok ? 'var(--ok)' : 'var(--bad)'} aria-hidden="true"></span>
            <span class="font-mono text-[13.5px]">{l.proto.toUpperCase()} {l.addr}:{l.port}</span>
            <span class:text-ok-fg={l.ok} class:text-bad-fg={!l.ok}>{l.ok ? 'listening' : l.error}</span>
          </li>
        {/each}
      </ul>
      <p class="mt-3 mb-0 text-[13px] text-muted">
        Host addresses: {st.host_ips.join(', ')} · <a class="text-link underline" href="#/welcome">Setup guide</a>
      </p>
    </section>
  {/if}
</div>

<style>
  dt {
    color: var(--muted);
    font-weight: 500;
  }
  dd {
    margin: 0;
  }
</style>

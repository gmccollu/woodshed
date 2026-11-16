<script lang="ts">
  import { openLive, type Listener } from '../lib/api';
  import { dateTime } from '../lib/format';
  import { firstDevice, live, refreshDevices, refreshStatus } from '../lib/status.svelte';
  import CopyButton from '../components/CopyButton.svelte';
  import Icon from '../components/Icon.svelte';

  type OS = 'macos' | 'linux' | 'windows';
  const OSES: OS[] = ['macos', 'linux', 'windows'];
  const OS_LABEL: Record<OS, string> = { macos: 'macOS', linux: 'Linux', windows: 'Windows' };

  const st = $derived(live.status);
  const okListeners = $derived(st?.listeners.filter((l) => l.ok) ?? []);
  const serverOS = $derived<OS>(
    st?.os.startsWith('windows') ? 'windows' : st?.os.startsWith('linux') ? 'linux' : 'macos',
  );
  let picked = $state<OS | null>(null);
  const os = $derived(picked ?? serverOS);

  // Send the test message to a listener that's actually up, preferring UDP.
  const target = $derived(okListeners.find((l) => l.proto === 'udp') ?? okListeners[0]);
  const host = (l: Listener) => (l.addr === '0.0.0.0' || l.addr === '::' ? '127.0.0.1' : l.addr);

  function command(o: OS, l: Listener): string {
    const h = host(l);
    const msg = '<14>woodshed-test: Hello from Woodshed';
    if (o === 'windows') {
      return l.proto === 'udp'
        ? `$c = New-Object System.Net.Sockets.UdpClient; $b = [Text.Encoding]::ASCII.GetBytes('${msg}'); [void]$c.Send($b, $b.Length, '${h}', ${l.port}); $c.Close()`
        : `$c = New-Object System.Net.Sockets.TcpClient('${h}', ${l.port}); $b = [Text.Encoding]::ASCII.GetBytes("${msg}\`n"); $c.GetStream().Write($b, 0, $b.Length); $c.Close()`;
    }
    if (o === 'linux') {
      return `logger ${l.proto === 'udp' ? '--udp' : '--tcp'} --server ${h} --port ${l.port} "Hello from Woodshed"`;
    }
    return `echo '${msg}' | nc ${l.proto === 'udp' ? '-u ' : ''}-w1 ${h} ${l.port}`;
  }
  const shell: Record<OS, string> = { macos: 'Terminal', linux: 'a terminal', windows: 'PowerShell' };

  // A live message only means "check now": the stream shows the latest messages, not the
  // first, so the time comes from first_message_at and the name from the earliest first_seen.
  let heard = $state(false);
  const received = $derived(!!st?.first_message_at);
  const fromDevice = $derived(received ? firstDevice() : undefined);

  // /api/status.first_message_at is the authority. The live stream is watched too, so the
  // page reacts at once and can show the line itself (the replay on connect also counts).
  $effect(() => {
    const close = openLive(
      {},
      {
        onMessage() {
          if (!heard) {
            heard = true;
            refreshDevices();
            refreshStatus();
          }
        },
      },
    );
    return close;
  });

  const listenerText = (l: Listener) =>
    `${l.proto.toUpperCase()} ${l.port}${l.addr === '0.0.0.0' || l.addr === '::' ? ' on all addresses' : ` on ${l.addr}`}`;
</script>

<div class="mx-auto max-w-4xl space-y-4">
  <section class="card text-center">
    <div class="mx-auto mb-2 grid size-14 place-items-center rounded-full bg-chip shadow-[var(--shadow-chip)]">
      <span class="pulse" class:still={!okListeners.length} aria-hidden="true"></span>
    </div>
    <h1 class="m-0 text-3xl font-bold tracking-tight">
      {#if !st}Starting…{:else if okListeners.length}Woodshed is listening{:else}Woodshed can't listen yet{/if}
    </h1>
    <p class="mx-auto mt-2 mb-0 max-w-xl text-[15px] text-muted">
      Point your devices' syslog at this machine. Every message is kept as plain text files, within a disk budget.
    </p>
  </section>

  <div class="grid gap-4 md:grid-cols-2">
    <section class="card">
      <h2 class="card-title">Send logs to</h2>
      <ul class="m-0 list-none space-y-2 p-0">
        {#each st?.host_ips ?? [] as ip (ip)}
          <li class="flex items-center justify-between gap-2">
            <code class="truncate font-mono text-[15px] font-semibold">{ip}</code>
            <CopyButton text={ip} />
          </li>
        {/each}
      </ul>
      <p class="mt-3 mb-0 text-[13px] text-muted">This machine's addresses. Use the one your devices can reach.</p>
      <p class="mt-2 mb-0 text-[13px]"><a class="text-link underline" href="#/device-setup">Configuration for your device: Set up a device</a></p>
    </section>

    <section class="card">
      <h2 class="card-title">Listeners</h2>
      <ul class="m-0 list-none space-y-2.5 p-0">
        {#each st?.listeners ?? [] as l (l.proto + l.port)}
          <li class="flex items-start gap-2.5">
            <span class="mt-1.5 inline-block size-[9px] shrink-0 rounded-full" style:background={l.ok ? 'var(--ok)' : 'var(--bad)'} aria-hidden="true"></span>
            <div>
              <div class="font-semibold">{listenerText(l)}</div>
              <div class="text-[13px]" class:text-ok-fg={l.ok} class:text-bad-fg={!l.ok}>
                {l.ok ? 'Listening' : `Not listening: ${l.error}${l.holder ? ` (held by ${l.holder})` : ''}`}
              </div>
            </div>
          </li>
        {/each}
      </ul>
      {#if st?.listeners.some((l) => !l.ok)}
        <p class="mt-3 mb-0 text-[13px] text-muted">See the banner above to retry, or change the port in <a class="text-link underline" href="#/settings">Settings</a>.</p>
      {/if}
    </section>
  </div>

  <section class="card">
    <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h2 class="card-title m-0">Send a test message from this machine</h2>
      <div class="seg" role="tablist" aria-label="Operating system">
        {#each OSES as o (o)}
          <button role="tab" aria-selected={os === o} onclick={() => (picked = o)}>{OS_LABEL[o]}</button>
        {/each}
      </div>
    </div>
    {#if target}
      <p class="mt-0 mb-2 text-[14px]">Run this in {shell[os]}. It sends one message to {listenerText(target)}.</p>
      <div class="log-panel flex items-start gap-3 rounded-2xl p-4">
        <code class="grow text-[13px] leading-relaxed break-all whitespace-pre-wrap">{command(os, target)}</code>
        <CopyButton text={command(os, target)} />
      </div>
    {:else}
      <p class="m-0 text-[14px]">No listener is up yet, so there's nowhere to send a test message.</p>
    {/if}
  </section>

  <section class="card" aria-live="polite">
    {#if received}
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="m-0 flex items-center gap-2 text-lg font-bold"><span class="text-ok-fg"><Icon name="check" size={20} /></span>First message received</h2>
          <p class="mt-1 mb-0 text-[14px] text-muted">
            {#if fromDevice}From {fromDevice.name || fromDevice.ip}{fromDevice.name ? ` (${fromDevice.ip})` : ''} at {dateTime(st!.first_message_at!)}.{:else}At {dateTime(st!.first_message_at!)}.{/if}
          </p>
        </div>
        <a class="pill-btn no-underline" href="#/dashboard">Open the dashboard <Icon name="arrow" size={15} /></a>
      </div>
    {:else}
      <div class="flex items-center gap-3">
        <span class="wait" aria-hidden="true"></span>
        <div>
          <h2 class="m-0 text-lg font-bold">Waiting for the first message…</h2>
          <p class="mt-1 mb-0 text-[14px] text-muted">This updates by itself when one arrives.</p>
        </div>
        <a class="ml-auto text-[14px] text-link underline" href="#/dashboard">Skip to the dashboard</a>
      </div>
    {/if}
  </section>
</div>

<style>
  .pulse {
    display: block;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok) 60%, transparent);
    animation: pulse 2s infinite;
  }
  .pulse.still {
    background: var(--bad);
    animation: none;
  }
  @keyframes pulse {
    70% {
      box-shadow: 0 0 0 14px transparent;
    }
    100% {
      box-shadow: 0 0 0 0 transparent;
    }
  }
  .wait {
    width: 22px;
    height: 22px;
    border-radius: 50%;
    border: 3px solid var(--divider);
    border-top-color: var(--spark);
    animation: spin 1s linear infinite;
    flex-shrink: 0;
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .seg {
    display: flex;
    background: var(--glass);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 3px;
  }
  .seg button {
    border: 0;
    background: transparent;
    color: var(--fg);
    padding: 5px 12px;
    border-radius: 999px;
    font-size: 13px;
    cursor: pointer;
  }
  .seg button[aria-selected='true'] {
    background: var(--chip);
    font-weight: 600;
    box-shadow: var(--shadow-chip);
  }
</style>

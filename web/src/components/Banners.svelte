<script lang="ts">
  import { dismissUpdate, getUpdates, putUpdates, retryListeners, type Banner, type Listener } from '../lib/api';
  import { live, refreshStatus } from '../lib/status.svelte';
  import { dismiss, isDismissed, prune } from '../lib/alerts.svelte';
  import { undo, undoLastSave } from '../lib/undo.svelte';
  import { go, router } from '../lib/router.svelte';
  import Icon from './Icon.svelte';

  // The install guide's container notes (raising net.core.rmem_max on the host).
  const CONTAINERS_DOC = 'https://github.com/gmccollu/woodshed/blob/main/docs/install.md#containers-lxc-docker-kubernetes';

  let retrying = $state(false);
  let retryError = $state('');

  const failed = $derived(live.status?.listeners.filter((l) => !l.ok) ?? []);
  const shown = $derived((live.status?.banners ?? []).filter((b) => !isDismissed(b)));

  // A dismissed banner that goes away and comes back is a new occurrence: show it again.
  $effect(() => {
    if (live.status) prune(live.status.banners);
  });

  /** One line per failed listener; plain words when the holder is another Woodshed. */
  function holderText(l: Listener): string {
    const port = `port ${l.port}`;
    if (l.holder_kind === 'woodshed_service')
      return `Another copy of Woodshed is using ${port}: the installed service. This copy can't receive logs; stop it, or use the service's page.`;
    if (l.holder_kind === 'woodshed')
      return `Another copy of Woodshed is using ${port}. This copy can't receive logs; stop the other copy, or use its page.`;
    return `${l.proto.toUpperCase()} ${l.addr}:${l.port}: ${l.error}${l.holder ? ` (held by ${l.holder})` : ''}`;
  }
  const isWoodshed = (l: Listener) => l.holder_kind === 'woodshed_service' || l.holder_kind === 'woodshed';
  // The same holder on UDP and TCP gets one sentence, not two.
  const lines = $derived.by(() => {
    const seen = new Set<string>();
    const out: { key: string; text: string; url: string }[] = [];
    for (const l of failed) {
      const text = holderText(l);
      const k = isWoodshed(l) ? `${l.holder_kind}:${l.port}` : `${l.proto}:${l.port}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push({ key: k, text, url: isWoodshed(l) ? (l.holder_ui_url ?? '') : '' });
    }
    return out;
  });

  /** Action tls_renew: open Settings → Syslog over TLS, where Renew is. It never renews by itself. */
  function openTls() {
    if (router.route === 'settings' && router.query === 'section=tls') {
      document.getElementById('tls')?.scrollIntoView({ block: 'start', behavior: 'instant' });
      return;
    }
    go('settings', 'section=tls');
  }

  // The update check's banners (docs/api.md → Update check): the one-time question, and a
  // newer version. Both answers and the dismissal are saved on the server, for everyone.
  let updateBusy = $state(false);
  let updateError = $state('');

  async function chooseUpdates(check: 'on' | 'off') {
    updateBusy = true;
    updateError = '';
    try {
      await putUpdates(check);
      await refreshStatus();
    } catch (e) {
      updateError = (e as Error).message;
    } finally {
      updateBusy = false;
    }
  }

  async function dismissNewVersion() {
    updateBusy = true;
    updateError = '';
    try {
      const u = await getUpdates();
      if (u.latest) await dismissUpdate(u.latest.version);
      await refreshStatus();
    } catch (e) {
      updateError = (e as Error).message;
    } finally {
      updateBusy = false;
    }
  }

  /** The release link, only when it points into this build's releases page (the server checks it too). */
  function releaseLink(b: Banner): string {
    const base = live.status?.releases_url ?? '';
    const u = b.url ?? '';
    return base && (u === base || u.startsWith(base + '/')) ? u : '';
  }

  async function retry() {
    retrying = true;
    retryError = '';
    try {
      await retryListeners();
      await refreshStatus();
      if (live.status?.listeners.some((l) => !l.ok)) retryError = 'Still failing. Check the other program is stopped, then try again.';
    } catch (e) {
      retryError = (e as Error).message;
    } finally {
      retrying = false;
    }
  }

</script>

{#if live.statusError}
  <div class="banner error" role="alert">
    <Icon name="alert" />
    <div class="grow">Can't reach the Woodshed service ({live.statusError}). Retrying every 5 s.</div>
  </div>
{/if}
{#each shown as b, i (`${i}:${b.kind}`)}
  <div class="banner {b.level}" role={b.level === 'error' ? 'alert' : 'status'}>
    <Icon name="alert" />
    <div class="grow">
      <div>{b.text}</div>
      {#if b.kind === 'device_limit'}
        <div class="detail-text">
          The limits stop a flood of fake source addresses from filling the device list. If these are real devices, raise the limits in
          <a class="text-link underline" href="#/settings?section=limits">Settings → Sender limits</a>.
        </div>
      {/if}
      {#if b.kind === 'retention_cap'}
        <div class="detail-text">
          Older logs are deleted to stay under the size cap. To keep more, raise the cap in
          <a class="text-link underline" href="#/settings?section=storage">Settings → Storage</a>.
        </div>
      {/if}
      {#if b.kind === 'udp_buffer_small'}
        <div class="detail-text">
          How to raise it, on the host or in a container:
          <a class="text-link underline" href={CONTAINERS_DOC} target="_blank" rel="noopener noreferrer">Install guide → Containers</a>.
        </div>
      {/if}
      {#if b.kind === 'udp_queue_full'}
        <div class="detail-text">
          The queue's size is set in the config file (woodshed.toml, not in Settings); restart Woodshed after changing it. Its hourly
          history is on the <a class="text-link underline" href="#/about">About page</a>.
        </div>
      {/if}
      {#if b.kind === 'tls_legacy'}
        <div class="detail-text">
          Turn it off in <a class="text-link underline" href="#/settings?section=tls">Settings → Syslog over TLS</a>.
        </div>
      {/if}
      {#if b.kind === 'tls_firewall'}
        <div class="detail-text">
          Open a Command Prompt or PowerShell with <b>Run as administrator</b>. The command is also in
          <a class="text-link underline" href="#/settings?section=tls">Settings → Syslog over TLS</a>.
        </div>
      {/if}
      {#if b.kind === 'listener_bind'}
        {#each lines as ln (ln.key)}
          <div class="detail-text" data-holder>
            {ln.text}
            {#if ln.url}<a class="text-link underline" href={ln.url}>Open the service's page</a>{/if}
          </div>
        {/each}
        {#if undo.saved}
          <div class="detail-text">This started with your last settings change ({undo.saved.broke}).</div>
        {/if}
        {#if undo.error}<div class="detail-text" role="status">{undo.error}</div>{/if}
      {/if}
      {#if b.kind === 'update_prompt'}
        <div class="detail-text">You can change this any time in <a class="text-link underline" href="#/settings?section=updates">Settings → Updates</a>.</div>
      {/if}
      {#if b.kind === 'update_available' && releaseLink(b)}
        <div class="detail-text">
          <a class="text-link underline" href={releaseLink(b)} target="_blank" rel="noopener noreferrer">What's new, and the downloads</a>.
          Woodshed doesn't update itself: run the new installer, and your settings and logs are kept.
        </div>
      {/if}
      {#if (b.action === 'update_choice' || b.action === 'update_dismiss') && updateError}<div class="detail-text" role="status">{updateError}</div>{/if}
      {#if b.action === 'retry_listeners' && retryError}<div class="detail" role="status">{retryError}</div>{/if}
    </div>
    <div class="actions">
      {#if b.action === 'update_choice'}
        <button class="pill-btn" onclick={() => chooseUpdates('on')} disabled={updateBusy}>Turn on</button>
        <button class="ghost-btn" onclick={() => chooseUpdates('off')} disabled={updateBusy}>No thanks</button>
      {/if}
      {#if b.kind === 'listener_bind' && undo.saved}
        <button class="pill-btn" onclick={undoLastSave} disabled={undo.busy}>
          <Icon name="retry" size={15} />{undo.busy ? 'Undoing…' : 'Undo last save'}
        </button>
      {/if}
      {#if b.action === 'tls_renew'}
        <button class="pill-btn" onclick={openTls}>Open TLS settings</button>
      {/if}
      {#if b.action === 'retry_listeners'}
        <button class={b.kind === 'listener_bind' && undo.saved ? 'ghost-btn' : 'pill-btn'} onclick={retry} disabled={retrying}>
          <Icon name="retry" size={15} />{retrying ? 'Retrying…' : 'Retry'}
        </button>
      {/if}
      {#if b.action === 'update_dismiss'}
        <button class="x" onclick={dismissNewVersion} disabled={updateBusy} aria-label="Hide this until a newer version" title="Hide this version's notice, for everyone">
          <Icon name="x" size={15} />
        </button>
      {:else if b.action !== 'update_choice'}
        <button class="x" onclick={() => dismiss(b)} aria-label="Hide this alert" title={b.level === 'error' ? 'Hide until it changes or the page is reloaded' : 'Hide until it changes'}>
          <Icon name="x" size={15} />
        </button>
      {/if}
    </div>
  </div>
{/each}

<style>
  .banner {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 16px;
    border-radius: 18px;
    margin-bottom: 12px;
    font-size: 14px;
    line-height: 1.45;
    color: var(--fg);
    border: 1px solid;
  }
  .banner :global(svg) {
    margin-top: 1px;
  }
  .error {
    background: var(--error-bg);
    border-color: var(--error-border);
  }
  .error > :global(svg) {
    color: var(--bad-fg);
  }
  .warn {
    background: var(--warn-bg);
    border-color: var(--warn-border);
  }
  .warn > :global(svg) {
    color: var(--warn-fg);
  }
  .info {
    background: var(--info-bg);
    border-color: var(--info-border);
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: flex-end;
    gap: 6px;
  }
  .x {
    display: grid;
    place-items: center;
    width: 30px;
    height: 30px;
    border-radius: 50%;
    border: 0;
    background: transparent;
    color: var(--fg);
    cursor: pointer;
  }
  .x:hover {
    background: var(--glass-strong);
  }
  .detail-text {
    margin-top: 4px;
    font-size: 13.5px;
  }
  .detail {
    margin-top: 4px;
    font-family: var(--font-mono);
    font-size: 12.5px;
  }
</style>

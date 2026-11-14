<script lang="ts">
  // The block confirmation, the device context menu and the toast (see lib/block.svelte.ts).
  import { askBlock, blockUi, closeToast, confirmBlock, targetLabel, unblock } from '../lib/block.svelte';

  let menuEl: HTMLDivElement | undefined = $state();
  let cancelBtn: HTMLButtonElement | undefined = $state();

  $effect(() => {
    if (!blockUi.menu && !blockUi.confirm) return;
    const key = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        blockUi.menu = null;
        blockUi.confirm = null;
      }
    };
    const down = (e: MouseEvent) => {
      if (blockUi.menu && menuEl && !menuEl.contains(e.target as Node)) blockUi.menu = null;
    };
    addEventListener('keydown', key);
    addEventListener('mousedown', down);
    return () => {
      removeEventListener('keydown', key);
      removeEventListener('mousedown', down);
    };
  });

  $effect(() => {
    if (blockUi.confirm) cancelBtn?.focus();
  });
  $effect(() => {
    if (blockUi.menu) menuEl?.querySelector('button')?.focus();
  });

  // Keep the menu inside the window.
  const pos = $derived(blockUi.menu ? { x: Math.min(blockUi.menu.x, innerWidth - 240), y: Math.min(blockUi.menu.y, innerHeight - 80 - 38 * blockUi.menu.extra.length) } : null);
</script>

{#if blockUi.menu && pos}
  <div bind:this={menuEl} class="menu glass" role="menu" aria-label="Sender {targetLabel(blockUi.menu.target)}" style:left="{pos.x}px" style:top="{pos.y}px">
    <div class="menu-head">{targetLabel(blockUi.menu.target)}</div>
    {#each blockUi.menu.extra as item (item.label)}
      <button
        role="menuitem"
        onclick={() => {
          blockUi.menu = null;
          item.run();
        }}>{item.label}</button
      >
    {/each}
    {#if blockUi.menu.blocked}
      <button role="menuitem" onclick={() => blockUi.menu && unblock(blockUi.menu.target.id)}>Unblock this sender</button>
    {:else}
      <button role="menuitem" onclick={() => blockUi.menu && askBlock(blockUi.menu.target.id)}>Block this sender…</button>
    {/if}
  </div>
{/if}

{#if blockUi.confirm}
  <div class="scrim" role="presentation" onclick={() => (blockUi.confirm = null)}></div>
  <div class="dialog glass" role="alertdialog" aria-modal="true" aria-labelledby="blk-t" aria-describedby="blk-d">
    <h2 id="blk-t" class="m-0 text-[18px] font-bold">Block {targetLabel(blockUi.confirm)}?</h2>
    <p id="blk-d" class="mt-2 mb-0 text-[14.5px]">Woodshed will refuse and count its messages. Its existing logs stay searchable.</p>
    {#if blockUi.error}<p class="mt-2 mb-0 text-[13.5px] font-medium text-bad-fg" role="alert">{blockUi.error}</p>{/if}
    <div class="mt-4 flex justify-end gap-2">
      <button bind:this={cancelBtn} class="ghost-btn" onclick={() => (blockUi.confirm = null)}>Cancel</button>
      <button class="pill-btn" onclick={confirmBlock} disabled={blockUi.busy}>{blockUi.busy ? 'Blocking…' : 'Block'}</button>
    </div>
  </div>
{/if}

{#if blockUi.toast}
  <div class="toast" role="status" aria-live="polite">
    <span>{blockUi.toast.text}</span>
    {#if blockUi.toast.link}<a class="text-link underline" href={blockUi.toast.link.href} onclick={closeToast}>{blockUi.toast.link.text}</a>{/if}
    {#if blockUi.toast.undo}
      <button
        class="ghost-btn"
        onclick={() => {
          const u = blockUi.toast?.undo;
          closeToast();
          u?.();
        }}>Undo</button
      >
    {/if}
    <button class="close" onclick={closeToast} aria-label="Close">×</button>
  </div>
{/if}

<style>
  .menu {
    position: fixed;
    z-index: 70;
    min-width: 220px;
    padding: 6px;
    border-radius: 14px;
    background: var(--glass-strong);
    box-shadow: var(--shadow);
    -webkit-backdrop-filter: blur(16px);
    backdrop-filter: blur(16px);
  }
  .menu-head {
    padding: 6px 10px;
    font-size: 12px;
    color: var(--muted);
    font-family: var(--font-mono);
  }
  .menu button {
    display: block;
    width: 100%;
    text-align: left;
    padding: 8px 10px;
    border: 0;
    border-radius: 10px;
    background: transparent;
    color: var(--fg);
    font: inherit;
    font-size: 14px;
    cursor: pointer;
  }
  .menu button:hover,
  .menu button:focus-visible {
    background: var(--glass);
  }
  .scrim {
    position: fixed;
    inset: 0;
    z-index: 70;
    background: rgba(10, 12, 16, 0.45);
  }
  .dialog {
    position: fixed;
    z-index: 71;
    left: 50%;
    top: 30%;
    transform: translate(-50%, -30%);
    width: min(460px, calc(100vw - 32px));
    padding: 22px;
    border-radius: 22px;
    background: var(--glass-strong);
    box-shadow: var(--shadow);
    -webkit-backdrop-filter: blur(20px);
    backdrop-filter: blur(20px);
  }
  .toast {
    position: fixed;
    z-index: 72;
    left: 50%;
    bottom: 24px;
    transform: translateX(-50%);
    display: flex;
    align-items: center;
    gap: 12px;
    max-width: calc(100vw - 32px);
    padding: 10px 12px 10px 18px;
    border-radius: 999px;
    background: var(--btn);
    color: var(--btn-fg);
    box-shadow: var(--shadow);
    font-size: 14px;
  }
  .toast .text-link {
    color: inherit;
  }
  .toast :global(.ghost-btn) {
    padding: 4px 12px;
  }
  .close {
    border: 0;
    background: transparent;
    color: inherit;
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    padding: 0 4px;
  }
</style>

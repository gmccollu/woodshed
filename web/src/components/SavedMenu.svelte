<script lang="ts">
  // The Saved menu on Events (SPEC §10.1.4): open, save, save as, rename, delete and copy a
  // link. Saved searches live on the server and are shared by everyone who can open the UI.
  import {
    ApiError,
    createSavedSearch,
    deleteSavedSearch,
    isConflict,
    listSavedSearches,
    updateSavedSearch,
    type SavedQuery,
    type SavedSearch,
  } from '../lib/api';
  import Icon from './Icon.svelte';

  let {
    type = 'syslog',
    current,
    etag,
    query,
    changed,
    linkOf,
    onopen,
    onsaved,
    ondeleted,
  }: {
    /** The data type the list shows and new searches are saved as (1.2: "trap" too). */
    type?: string;
    current: SavedSearch | null;
    etag: string;
    /** The form as a saved query, for Save and Save as. */
    query: () => SavedQuery;
    changed: boolean;
    /** The page link that opens a saved search. */
    linkOf: (s: SavedSearch) => string;
    onopen: (s: SavedSearch) => void;
    onsaved: (s: SavedSearch, etag: string) => void;
    ondeleted: (id: string) => void;
  } = $props();

  let open = $state(false);
  let list = $state<SavedSearch[] | null>(null);
  let listError = $state('');
  /** The inline name form: a new search (save as) or a rename. */
  let naming = $state<{ kind: 'new' } | { kind: 'rename'; s: SavedSearch } | null>(null);
  let name = $state('');
  let nameError = $state('');
  let busy = $state(false);
  let confirmDelete = $state('');
  let copied = $state('');
  let root: HTMLDivElement | undefined = $state();
  let nameInput: HTMLInputElement | undefined = $state();

  async function load() {
    try {
      list = await listSavedSearches(type);
      listError = '';
    } catch (x) {
      listError = (x as Error).message;
    }
  }

  function toggle() {
    open = !open;
    naming = null;
    confirmDelete = '';
    if (open) load();
  }

  $effect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (root && !root.contains(e.target as Node)) open = false;
    };
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') open = false;
    };
    addEventListener('mousedown', away);
    addEventListener('keydown', esc);
    return () => {
      removeEventListener('mousedown', away);
      removeEventListener('keydown', esc);
    };
  });

  function startName(n: typeof naming) {
    naming = n;
    name = n?.kind === 'rename' ? n.s.name : current ? `${current.name} (copy)` : '';
    nameError = '';
    requestAnimationFrame(() => nameInput?.select());
  }

  /** The error to show for a failed save: the name's own message, a clash, or the query's. */
  function saveError(x: unknown): string {
    if (x instanceof ApiError && Object.keys(x.fields).length) {
      return Object.entries(x.fields)
        .map(([k, v]) => (k === 'name' ? v : `${k.replace(/^query\./, '')}: ${v}`))
        .join(' ');
    }
    return (x as Error).message;
  }

  async function submitName(e: SubmitEvent) {
    e.preventDefault();
    if (!naming) return;
    busy = true;
    nameError = '';
    try {
      if (naming.kind === 'new') {
        const s = await createSavedSearch({ name, type, query: query() });
        onsaved(s, '');
      } else {
        const s0 = naming.s;
        const { saved, etag: tag } = await updateSavedSearch(s0.id, { name, type: s0.type, query: s0.query }, current?.id === s0.id ? etag : '');
        if (current?.id === saved.id) onsaved(saved, tag);
      }
      naming = null;
      await load();
    } catch (x) {
      nameError = saveError(x);
    } finally {
      busy = false;
    }
  }

  let saveMsg = $state('');
  async function save() {
    if (!current) return;
    busy = true;
    saveMsg = '';
    try {
      const { saved, etag: tag } = await updateSavedSearch(current.id, { name: current.name, type: current.type, query: query() }, etag);
      onsaved(saved, tag);
      saveMsg = 'Saved.';
      await load();
    } catch (x) {
      saveMsg = isConflict(x) ? `${(x as Error).message} Open it again to see the change, or Save as a new one.` : saveError(x);
    } finally {
      busy = false;
    }
  }

  async function remove(s: SavedSearch) {
    busy = true;
    try {
      await deleteSavedSearch(s.id);
      ondeleted(s.id);
      confirmDelete = '';
      await load();
    } catch (x) {
      listError = (x as Error).message;
    } finally {
      busy = false;
    }
  }

  async function copy(s: SavedSearch) {
    const text = linkOf(s);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    copied = s.id;
    setTimeout(() => (copied = ''), 1500);
  }
</script>

<div class="saved" bind:this={root}>
  <button type="button" class="ghost-btn" aria-haspopup="true" aria-expanded={open} onclick={toggle}>
    Saved <span aria-hidden="true">▾</span>
  </button>
  {#if open}
    <div class="menu" role="dialog" aria-label="Saved searches">
      <div class="acts">
        <button type="button" class="pill-btn" disabled={!current || !changed || busy} onclick={save} title={current ? `Update "${current.name}" with the form` : 'Open a saved search first'}>
          Save
        </button>
        <button type="button" class="ghost-btn" disabled={busy} onclick={() => startName({ kind: 'new' })}>Save as…</button>
        {#if saveMsg}<span class="msg" role="status">{saveMsg}</span>{/if}
      </div>
      {#if naming}
        <form class="nameform" onsubmit={submitName}>
          <label class="lab" for="ss-name">{naming.kind === 'new' ? 'Name for this search' : `Rename "${naming.s.name}"`}</label>
          <div class="flex gap-2">
            <input id="ss-name" class="field" bind:this={nameInput} bind:value={name} maxlength="200" autocomplete="off" aria-invalid={!!nameError} aria-describedby="ss-err" />
            <button type="submit" class="pill-btn" disabled={busy}>{naming.kind === 'new' ? 'Save' : 'Rename'}</button>
            <button type="button" class="ghost-btn" onclick={() => (naming = null)}>Cancel</button>
          </div>
          {#if nameError}<p id="ss-err" class="err" role="alert">{nameError}</p>{/if}
        </form>
      {/if}
      {#if listError}<p class="err" role="alert">{listError}</p>{/if}
      {#if list === null && !listError}
        <p class="dim">Loading…</p>
      {:else if list && !list.length}
        <p class="dim">No saved searches yet. Set up a search, then Save as… to keep it for everyone who uses this Woodshed.</p>
      {:else if list}
        <ul>
          {#each list as s (s.id)}
            <li class:cur={current?.id === s.id}>
              <button type="button" class="open" onclick={() => { open = false; onopen(s); }} title="Open “{s.name}”">
                <span class="nm">{s.name}</span>
                {#if s.missing_devices.length || s.missing_group}<span class="warn" title="Some devices it names are no longer known">⚠</span>{/if}
              </button>
              {#if confirmDelete === s.id}
                <span class="confirm">Delete? <button type="button" class="lnk bad" onclick={() => remove(s)}>Yes</button> <button type="button" class="lnk" onclick={() => (confirmDelete = '')}>No</button></span>
              {:else}
                <button type="button" class="ico" aria-label="Copy a link to “{s.name}”" title="Copy link" onclick={() => copy(s)}><Icon name={copied === s.id ? 'check' : 'copy'} size={14} /></button>
                <button type="button" class="ico" aria-label="Rename “{s.name}”" title="Rename" onclick={() => startName({ kind: 'rename', s })}><Icon name="edit" size={14} /></button>
                <button type="button" class="ico" aria-label="Delete “{s.name}”" title="Delete" onclick={() => (confirmDelete = s.id)}><Icon name="trash" size={14} /></button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
</div>

<style>
  .saved {
    position: relative;
  }
  .menu {
    position: absolute;
    right: 0;
    top: calc(100% + 6px);
    z-index: 40;
    width: min(26rem, calc(100vw - 32px));
    padding: 12px;
    border-radius: 16px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
    -webkit-backdrop-filter: blur(20px);
    backdrop-filter: blur(20px);
    font-size: 13px;
  }
  .acts {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .msg {
    color: var(--muted);
  }
  .nameform {
    margin: 4px 0 10px;
  }
  .lab {
    display: block;
    margin-bottom: 4px;
    font-size: 12.5px;
    font-weight: 600;
    color: var(--muted);
  }
  .err {
    margin: 4px 0;
    color: var(--bad-fg);
    font-weight: 500;
  }
  .dim {
    margin: 4px 0;
    color: var(--muted);
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    max-height: 22rem;
    overflow: auto;
  }
  li {
    display: flex;
    align-items: center;
    gap: 2px;
    border-radius: 10px;
    padding: 1px 2px;
  }
  li.cur {
    background: var(--chip);
  }
  .open {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1 1 auto;
    min-width: 0;
    padding: 6px 8px;
    border: 0;
    background: transparent;
    color: var(--fg);
    text-align: left;
    cursor: pointer;
    border-radius: 8px;
  }
  .open:hover {
    background: var(--chip);
  }
  .nm {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .warn {
    color: var(--warn-fg);
  }
  .ico {
    display: inline-flex;
    padding: 5px;
    border: 0;
    border-radius: 8px;
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }
  .ico:hover {
    color: var(--fg);
    background: var(--chip);
  }
  .confirm {
    white-space: nowrap;
    color: var(--fg);
  }
  .lnk {
    border: 0;
    background: transparent;
    color: var(--link);
    cursor: pointer;
    font-weight: 600;
    padding: 2px 4px;
  }
  .lnk.bad {
    color: var(--bad-fg);
  }
</style>

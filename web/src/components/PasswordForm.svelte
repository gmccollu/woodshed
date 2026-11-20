<script lang="ts">
  // Sets or changes the UI password (PUT /api/password). It lives inside the Settings
  // <form>, so it uses a group and handles Enter itself instead of nesting a form.
  import { ApiError, putPassword } from '../lib/api';
  import { auth, loadSession, login } from '../lib/session.svelte';

  let { onchange }: { onchange?: () => void } = $props();

  let current = $state('');
  let next = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let done = $state('');
  let errs = $state<{ current?: string; new?: string; confirm?: string; form?: string }>({});

  const isSet = $derived(!!auth.session?.password_set);
  // docs/api.md: once a password is set, changing it needs the current one in both modes.
  const needCurrent = $derived(isSet);

  async function submit() {
    if (busy) return;
    errs = {};
    done = '';
    if (next !== confirm) {
      errs = { confirm: "The two passwords don't match." };
      return;
    }
    busy = true;
    try {
      const first = !isSet;
      const pw = next;
      await putPassword(needCurrent ? current : '', pw);
      current = next = confirm = '';
      if (first) {
        // docs/api.md: the first password also turns on require_login_local, so this machine
        // needs a login from now on. Log in with the password just set rather than bounce
        // to the login screen.
        try {
          await login(pw);
        } catch {
          /* the login screen will ask */
        }
        done = 'Password set. Login is now required on this machine too; you can turn that off above.';
      } else {
        done = 'Password changed. Other sessions were logged out.';
      }
      await loadSession();
      onchange?.();
    } catch (x) {
      const e = x as ApiError;
      if (e.status === 400 && e.fields?.new) errs = { new: e.fields.new };
      else if (e.status === 403) errs = { current: "The current password isn't right." };
      else if (e.status === 429) errs = { form: `Too many wrong passwords. Try again in ${Math.ceil((e.retryAfter || 60) / 60)} min.` };
      else errs = { form: e.message };
    } finally {
      busy = false;
    }
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'Enter') {
      e.preventDefault(); // don't submit the surrounding Settings form
      submit();
    }
  }
</script>

<div class="pw" role="group" aria-labelledby="pw-title">
  <h3 id="pw-title" class="m-0 text-[14px] font-semibold">{isSet ? 'Change password' : 'Set a password'}</h3>
  <p class="hint m-0">
    {isSet ? 'Used to log in when LAN mode is on.' : 'LAN mode needs a password first. At least 8 characters; a few words work well.'}
  </p>
  <div class="grid gap-3 sm:grid-cols-3">
    {#if needCurrent}
      <label class="lbl">
        <span>Current password</span>
        <input class="field" type="password" autocomplete="current-password" bind:value={current} onkeydown={onKey} aria-invalid={!!errs.current} />
        {#if errs.current}<span class="ferr">{errs.current}</span>{/if}
      </label>
    {/if}
    <label class="lbl">
      <span>New password</span>
      <input id="pw-new" class="field" type="password" autocomplete="new-password" bind:value={next} onkeydown={onKey} aria-invalid={!!errs.new} />
      {#if errs.new}<span class="ferr">{errs.new}</span>{/if}
    </label>
    <label class="lbl">
      <span>Repeat it</span>
      <input class="field" type="password" autocomplete="new-password" bind:value={confirm} onkeydown={onKey} aria-invalid={!!errs.confirm} />
      {#if errs.confirm}<span class="ferr">{errs.confirm}</span>{/if}
    </label>
  </div>
  <div class="flex flex-wrap items-center gap-3">
    <button type="button" class="pill-btn" onclick={submit} disabled={busy || !next || (needCurrent && !current)}>
      {busy ? 'Saving…' : isSet ? 'Change password' : 'Set password'}
    </button>
    <span aria-live="polite" class="text-[13.5px]">
      {#if errs.form}<span class="font-medium text-bad-fg">{errs.form}</span>{:else if done}<span class="text-ok-fg">{done}</span>{/if}
    </span>
  </div>
</div>

<style>
  .pw {
    display: flex;
    flex-direction: column;
    gap: 10px;
    border-top: 1px solid var(--divider);
    padding-top: 14px;
    margin-top: 14px;
  }
  .hint {
    font-size: 13px;
    color: var(--muted);
  }
  .lbl {
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: 13.5px;
    font-weight: 500;
  }
  .ferr {
    font-size: 13px;
    font-weight: 500;
    color: var(--bad-fg);
  }
</style>

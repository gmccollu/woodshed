// Blocking a sender (docs/api.md: PATCH /api/devices/{id} {"blocked": …}), shared by the
// dashboard chips, the Devices table, the live tail and search results: one confirmation
// dialog, one context menu and one toast (with Undo) for the whole app.
import { patchDevice, type Device } from './api';
import { knownDevice, replaceDevice } from './status.svelte';

interface Target {
  id: string;
  ip: string;
  name: string;
}

interface Toast {
  text: string;
  undo?: () => void;
  link?: { href: string; text: string };
}

export const blockUi = $state<{
  confirm: Target | null;
  menu: { x: number; y: number; target: Target; blocked: boolean; extra: MenuItem[] } | null;
  toast: Toast | null;
  busy: boolean;
  error: string;
  /** Bumped after every change, so lists reload. */
  version: number;
}>({ confirm: null, menu: null, toast: null, busy: false, error: '', version: 0 });

/** A page's own item in the menu, above the block item (Events: "Bundle around this"). */
export interface MenuItem {
  label: string;
  run: () => void;
}

export const targetLabel = (t: Target) => (t.name ? `${t.ip} (${t.name})` : t.ip);

function targetOf(id: string): Target {
  const d = knownDevice(id);
  return { id, ip: d?.ip ?? id, name: d?.name ?? '' };
}

let toastTimer = 0;
function toast(t: Toast, ms = 8000) {
  clearTimeout(toastTimer);
  blockUi.toast = t;
  if (ms) toastTimer = window.setTimeout(() => (blockUi.toast = null), ms);
}

export function closeToast() {
  clearTimeout(toastTimer);
  blockUi.toast = null;
}

/** Opens the "Block this sender?" confirmation. */
export function askBlock(id: string): void {
  blockUi.menu = null;
  blockUi.error = '';
  blockUi.confirm = targetOf(id);
}

/** Opens the small menu for a device at the pointer (right-click or the "⋯" button), with a page's own items first. */
export function openMenu(id: string, x: number, y: number, extra: MenuItem[] = []): void {
  const d = knownDevice(id);
  blockUi.menu = { x, y, target: targetOf(id), blocked: !!d?.blocked, extra };
}

async function setBlocked(t: Target, blocked: boolean): Promise<Device> {
  const d = await patchDevice(t.id, { blocked });
  replaceDevice(d);
  blockUi.version++;
  return d;
}

export async function confirmBlock(): Promise<void> {
  const t = blockUi.confirm;
  if (!t || blockUi.busy) return;
  blockUi.busy = true;
  blockUi.error = '';
  try {
    await setBlocked(t, true);
    blockUi.confirm = null;
    toast({ text: `Blocked ${targetLabel(t)}.`, undo: () => unblock(t.id, true) });
  } catch (e) {
    blockUi.error = (e as Error).message;
  } finally {
    blockUi.busy = false;
  }
}

/** Unblocks; says so when a broader blocklist entry still covers the device. */
export async function unblock(id: string, fromUndo = false): Promise<void> {
  const t = targetOf(id);
  blockUi.menu = null;
  try {
    const d = await setBlocked(t, false);
    if (d.blocked_by || d.blocked) {
      toast(
        {
          text: `Still blocked by ${d.blocked_by ?? 'an entry'} in Settings → Blocklist.`,
          link: { href: '#/settings?section=blocklist', text: 'Open the blocklist' },
        },
        0,
      );
    } else {
      toast(fromUndo ? { text: `${targetLabel(t)} is unblocked again.` } : { text: `Unblocked ${targetLabel(t)}.`, undo: () => askBlock(t.id) });
    }
  } catch (e) {
    toast({ text: `Couldn't unblock ${targetLabel(t)}: ${(e as Error).message}` });
  }
}

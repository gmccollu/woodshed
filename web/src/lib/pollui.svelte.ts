// The poll form's state, shared by the pages that open it (Devices, a device's page) and the one
// host in App.svelte that renders it. `version` goes up after every save or delete, so lists
// and panels read again.
import { getSettings } from './api';
import { getPollTarget } from './api';
import type { PollSettings, PollTarget } from './poll';

export const pollUi = $state<{
  form: { target: PollTarget | null; address: string; device: string } | null;
  defaults: PollSettings | null;
  version: number;
}>({ form: null, defaults: null, version: 0 });

/** Opens the form: a target to change, or a new one (prefilled for a device's address). */
export async function openPollForm(target: PollTarget | null, address = '', device = ''): Promise<void> {
  if (!pollUi.defaults) {
    try {
      pollUi.defaults = (await getSettings()).settings.poll ?? null;
    } catch {
      /* the server's defaults apply to fields left out */
    }
  }
  pollUi.form = { target, address, device };
}

/** Opens the form for a target by id (from a device page). */
export async function editPollTarget(id: string): Promise<void> {
  const { target } = await getPollTarget(id);
  await openPollForm(target);
}

export function closePollForm(saved = false): void {
  pollUi.form = null;
  if (saved) pollUi.version++;
}

// Settings → UI access: the address other machines type in LAN mode, and the two
// checkboxes that need a UI password first.

/** A TCP port number (1–65535). */
export function isPort(port: unknown): port is number {
  return typeof port === 'number' && Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * https://<addr>:<port>/ for each of the server's ui_addrs (IPv6 in brackets), or none for a port
 * that isn't one (an empty or out-of-range field while it's being edited).
 */
export function lanUrls(addrs: readonly string[], port: number | null | undefined): string[] {
  if (!isPort(port)) return [];
  return addrs.map((a) => `https://${a.includes(':') ? `[${a}]` : a}:${port}/`);
}

/**
 * Whether a click on a checkbox that needs a password (LAN mode, require login on localhost) is
 * refused: turning it on without a password is; turning it off never is.
 */
export function refusedWithoutPassword(passwordSet: boolean, checked: boolean): boolean {
  return !passwordSet && !checked;
}

/**
 * The form for fresh settings with the user's unsaved edits kept: each field the user changed
 * from base (the form as last loaded) is copied onto fresh, except the fields in `except`, which
 * take the fresh value. Setting the first password changes the settings (require_login_local
 * turns on), so they're read again, and that mustn't wipe what the user was in the middle of.
 */
export function keepEdits<T extends object>(base: T, mine: T, fresh: T, except: readonly (keyof T)[] = []): T {
  const out = { ...fresh };
  for (const k of Object.keys(mine) as (keyof T)[]) {
    if (except.includes(k)) continue;
    if (JSON.stringify(mine[k]) !== JSON.stringify(base[k])) out[k] = mine[k];
  }
  return out;
}

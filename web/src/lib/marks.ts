// The marks on a stored syslog message (2.0, docs/api.md → Search → Marks): it was cut
// at the max message size, or its TCP/TLS frame ended before all of it arrived.

import type { LogLine } from './api';
import { num } from './format.ts';

export interface Mark {
  /** Short text shown after the message. */
  label: string;
  /** The longer explanation, for the tooltip and screen readers. */
  title: string;
}

/** The line's marks, in the order the stored line has them; [] when it was stored whole. */
export function marks(l: Pick<LogLine, 'truncated' | 'incomplete' | 'frame_arrived' | 'frame_length'>): Mark[] {
  const out: Mark[] = [];
  if (l.truncated) {
    out.push({ label: 'truncated', title: 'Longer than the max message size: the rest was read and discarded.' });
  }
  if (l.incomplete) {
    const len = l.frame_length ?? 0;
    if (len > 0) {
      const got = l.frame_arrived ?? 0;
      out.push({
        label: `incomplete: ${num(got)} of ${num(len)} bytes`,
        title: `The connection ended before the whole message arrived: its frame said ${num(len)} bytes and ${num(got)} came. What arrived is stored.`,
      });
    } else {
      out.push({
        label: 'incomplete',
        title: 'Woodshed closed the connection (frame timeout, eviction or shutdown) before this line ended. What arrived is stored.',
      });
    }
  }
  return out;
}

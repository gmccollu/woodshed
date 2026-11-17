<script lang="ts">
  // A stored message's marks (lib/marks.ts), after its text in a log row.
  import type { LogLine } from '../lib/api';
  import { marks } from '../lib/marks';

  let { line }: { line: Pick<LogLine, 'truncated' | 'incomplete' | 'frame_arrived' | 'frame_length'> } = $props();
  const ms = $derived(marks(line));
</script>

{#each ms as m (m.label)}<span class="logmark" title={m.title}> [{m.label}]<span class="sr-only">. {m.title}</span></span>{/each}

<style>
  .logmark {
    color: var(--sev-warn);
  }
</style>

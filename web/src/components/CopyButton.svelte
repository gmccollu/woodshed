<script lang="ts">
  import Icon from './Icon.svelte';
  // name is the button's accessible name when the text is too long to read out (a snippet).
  let { text, label = 'Copy', name = '' }: { text: string; label?: string; name?: string } = $props();
  let done = $state(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API needs a secure context; fall back to a hidden textarea.
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    done = true;
    setTimeout(() => (done = false), 1500);
  }
</script>

<button type="button" class="ghost-btn" onclick={copy} aria-label={name || `${label}: ${text}`}>
  <Icon name={done ? 'check' : 'copy'} size={15} />
  <span aria-live="polite">{done ? 'Copied' : label}</span>
</button>

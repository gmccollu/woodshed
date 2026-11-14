<script lang="ts">
  // The bundle's size estimate (POST /api/exports/estimate with the bundle body) and the
  // Build the bundle button (POST /api/exports), which opens the Export list where it builds
  // like any export. `formError` holds what's wrong before asking the server at all.
  import { createBundle, estimateBundle, type ExportEstimate } from '../lib/api';
  import { bundleBody, type BundleForm } from '../lib/bundle';
  import { bytes, num } from '../lib/format';
  import { go } from '../lib/router.svelte';
  import Icon from './Icon.svelte';

  let { form, formError = '', children }: { form: BundleForm; formError?: string; children?: import('svelte').Snippet } = $props();

  let est = $state<ExportEstimate | null>(null);
  let estError = $state('');
  let estBusy = $state(false);
  $effect(() => {
    const body = bundleBody($state.snapshot(form) as BundleForm);
    void JSON.stringify(body);
    if (formError) {
      est = null;
      estError = '';
      return;
    }
    const ctrl = new AbortController();
    const t = setTimeout(async () => {
      estBusy = true;
      try {
        est = await estimateBundle(body, ctrl.signal);
        estError = '';
      } catch (x) {
        if ((x as Error).name !== 'AbortError') {
          est = null;
          estError = (x as Error).message;
        }
      } finally {
        estBusy = false;
      }
    }, 350);
    return () => {
      clearTimeout(t);
      ctrl.abort();
    };
  });

  let building = $state(false);
  let buildError = $state('');
  async function build() {
    if (formError || building) return;
    building = true;
    buildError = '';
    try {
      await createBundle(bundleBody($state.snapshot(form) as BundleForm));
      go('export');
    } catch (x) {
      buildError = (x as Error).message;
    } finally {
      building = false;
    }
  }
</script>

<div class="estimate" aria-live="polite" data-bundle-estimate>
  {#if formError}
    <span class="text-bad-fg font-medium">{formError}</span>
  {:else if estError}
    <span class="text-bad-fg font-medium">{estError}</span>
  {:else if est}
    <span>Up to <b>{num(est.lines)}</b> lines from <b>{num(est.files)}</b> file{est.files === 1 ? '' : 's'}, about <b>{bytes(est.bytes)}</b> before compression.</span>
    {#if estBusy}<span class="text-muted"> Updating…</span>{/if}
  {:else}
    <span class="text-muted">Estimating…</span>
  {/if}
</div>
<div class="flex flex-wrap items-center gap-3">
  <button type="button" class="pill-btn px-5 py-2.5" onclick={build} disabled={!!formError || building || !!estError}>
    <Icon name="export" size={15} />{building ? 'Starting…' : 'Build the bundle'}
  </button>
  {@render children?.()}
  {#if buildError}<span class="text-[13.5px] font-medium text-bad-fg" role="alert">{buildError}</span>{/if}
</div>

<style>
  .estimate {
    padding: 10px 14px;
    border-radius: 14px;
    background: var(--glass-strong);
    border: 1px solid var(--border);
    font-size: 14px;
  }
</style>

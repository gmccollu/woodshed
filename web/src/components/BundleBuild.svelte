<script lang="ts">
  // The bundle's size estimate (POST /api/exports/estimate with the bundle body) and the
  // Build the bundle button (POST /api/exports), which opens the Export list where it builds
  // like any export. `formError` holds what's wrong before asking the server at all.
  //
  // 2.0: flows go in by default; Leave flows out is offered (FlowOptions), and pre-selected for a
  // window over 4 h whose flows are estimated above 1 GB. The estimate asks with flows in first, so
  // the rule and the per-type line know their size, and again without them when they're left out.
  import { createBundle, estimateBundle, type DataType, type ExportEstimate } from '../lib/api';
  import { bundleBody, bundleWindow, type BundleForm } from '../lib/bundle';
  import { byTypeText, FLOW, flowEstimate, isTooManyFlows, leaveFlowsOutByDefault, type FlowFormat } from '../lib/flows';
  import { bytes, num } from '../lib/format';
  import { go } from '../lib/router.svelte';
  import FlowOptions from './FlowOptions.svelte';
  import Icon from './Icon.svelte';

  let {
    form,
    formError = '',
    types = [],
    children,
  }: { form: BundleForm; formError?: string; types?: DataType[]; children?: import('svelte').Snippet } = $props();

  const allTypes = $derived(types.map((t) => t.type));
  /** Whether this bundle can hold flows: the server has them, and the types choice includes them. */
  const flowsPossible = $derived(allTypes.includes(FLOW) && (!form.types.length || form.types.includes(FLOW)));
  let leave = $state<boolean | null>(null);
  let formats = $state<FlowFormat[]>(['csv', 'ipfix']);
  let flowEst = $state<{ records: number; bytes: number } | null>(null);
  let tooMany = $state('');
  const windowMs = $derived.by(() => {
    const w = bundleWindow(form.at, form.before, form.after);
    return typeof w === 'string' ? 0 : Date.parse(w.to) - Date.parse(w.from);
  });
  const auto = $derived(leaveFlowsOutByDefault(windowMs, flowEst?.bytes ?? 0) || !!tooMany);
  const noFlows = $derived(flowsPossible && (leave ?? auto));
  const body = (withFlows: boolean) =>
    bundleBody({ ...($state.snapshot(form) as BundleForm), noFlows: flowsPossible && !withFlows, flowFormats: [...formats] }, allTypes);

  let est = $state<ExportEstimate | null>(null);
  let estError = $state('');
  let estBusy = $state(false);
  $effect(() => {
    const key = JSON.stringify([body(true), noFlows, flowsPossible]);
    void key;
    if (formError) {
      est = null;
      estError = '';
      return;
    }
    const ctrl = new AbortController();
    const out = noFlows;
    const t = setTimeout(async () => {
      estBusy = true;
      try {
        let full: ExportEstimate | null = null;
        try {
          full = await estimateBundle(body(true), ctrl.signal);
          flowEst = flowEstimate(full.by_type);
          tooMany = '';
        } catch (x) {
          if (!(x instanceof Error) || !isTooManyFlows(x.message) || !flowsPossible) throw x;
          tooMany = x.message;
        }
        est = out || !full ? await estimateBundle(body(false), ctrl.signal) : full;
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
      await createBundle(body(!noFlows));
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
    <span>Up to <b>{num(est.lines)}</b> {est.by_type?.flow ? 'lines and records' : 'lines'} from <b>{num(est.files)}</b> file{est.files === 1 ? '' : 's'}, about <b>{bytes(est.bytes)}</b> before compression.</span>
    {#if est.by_type && byTypeText(est.by_type)}<span class="block text-[13px] text-muted">{byTypeText(est.by_type)}</span>{/if}
    {#if estBusy}<span class="text-muted"> Updating…</span>{/if}
  {:else}
    <span class="text-muted">Estimating…</span>
  {/if}
</div>
{#if flowsPossible}
  <FlowOptions bind:leave bind:formats {auto} flow={flowEst} tooMany={tooMany} idp="bfl" />
{/if}
<div class="flex flex-wrap items-center gap-3">
  <button type="button" class="pill-btn px-5 py-2.5" onclick={build} disabled={!!formError || building || !!estError || (!!tooMany && !noFlows)}>
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

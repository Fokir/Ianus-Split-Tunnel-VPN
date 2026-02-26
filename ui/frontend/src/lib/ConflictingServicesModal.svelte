<script>
  import { createEventDispatcher } from 'svelte';
  import { t } from './i18n';
  import * as api from './api.js';

  export let services = [];

  const dispatch = createEventDispatcher();

  let stopping = false;
  let resultMessage = '';
  let resultError = false;
  let dontShowAgain = false;

  async function handleStopAll() {
    stopping = true;
    resultMessage = '';
    try {
      const names = services.map(s => s.name);
      const result = await api.stopConflictingServices(names);
      if (result.success) {
        resultMessage = $t('conflicting.stopped');
        resultError = false;
        // Auto-close after success
        setTimeout(() => handleClose(), 1500);
      } else {
        const failedNames = (result.failed || []).join(', ');
        resultMessage = $t('conflicting.partialError').replace('{names}', failedNames);
        resultError = true;
      }
    } catch (err) {
      resultMessage = err.message || String(err);
      resultError = true;
    } finally {
      stopping = false;
    }
  }

  function handleClose() {
    if (dontShowAgain) {
      localStorage.setItem('hideConflictingServicesModal', 'true');
    }
    dispatch('close');
  }
</script>

<!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
<div
  class="fixed inset-0 bg-black/60 z-50 flex items-center justify-center"
  on:click|self={handleClose}
  on:keydown={e => e.key === 'Escape' && handleClose()}
  role="dialog"
  tabindex="-1"
>
  <div class="bg-zinc-800 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-5 space-y-4">
    <!-- Header -->
    <div class="flex items-start gap-3">
      <div class="p-2 bg-amber-500/10 rounded-lg shrink-0">
        <svg class="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="currentColor">
          <path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/>
        </svg>
      </div>
      <div>
        <h3 class="text-base font-semibold text-zinc-100">{$t('conflicting.title')}</h3>
        <p class="text-sm text-zinc-400 mt-1">{$t('conflicting.message')}</p>
      </div>
    </div>

    <!-- Service list -->
    <div class="space-y-2 max-h-48 overflow-y-auto">
      {#each services as svc}
        <div class="flex items-center gap-3 p-3 bg-zinc-900/60 rounded-lg border border-zinc-700/50">
          <div class="w-2 h-2 rounded-full bg-amber-400 shrink-0"></div>
          <div class="min-w-0 flex-1">
            <div class="text-sm font-medium text-zinc-200 truncate">{svc.displayName}</div>
            <div class="text-xs text-zinc-500 truncate">
              {svc.type === 'service' ? $t('conflicting.service') : $t('conflicting.process')}: {svc.name}
            </div>
          </div>
        </div>
      {/each}
    </div>

    <!-- Result message -->
    {#if resultMessage}
      <div class="text-sm px-3 py-2 rounded-lg {resultError ? 'bg-red-900/20 text-red-400 border border-red-700/40' : 'bg-green-900/20 text-green-400 border border-green-700/40'}">
        {resultMessage}
      </div>
    {/if}

    <!-- Don't show again -->
    <label class="flex items-center gap-2 cursor-pointer">
      <input type="checkbox" bind:checked={dontShowAgain}
        class="w-4 h-4 rounded border-zinc-600 bg-zinc-700 text-blue-500 focus:ring-blue-500/30" />
      <span class="text-xs text-zinc-500">{$t('conflicting.dontShowAgain')}</span>
    </label>

    <!-- Actions -->
    <div class="flex justify-end gap-2 pt-1">
      <button
        class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
        on:click={handleClose}
      >
        {$t('conflicting.ignore')}
      </button>
      <button
        class="px-4 py-2 text-sm rounded-lg bg-amber-600 text-white hover:bg-amber-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        on:click={handleStopAll}
        disabled={stopping}
      >
        {stopping ? $t('conflicting.stopping') : $t('conflicting.stopAll')}
      </button>
    </div>
  </div>
</div>

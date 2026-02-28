<script>
  import { createEventDispatcher } from 'svelte';
  import ProcessPicker from '../../ProcessPicker.svelte';
  import ErrorAlert from '../../ErrorAlert.svelte';
  import { EmptyState, Modal } from '../../components';
  import { t } from '../../i18n';
  import { isMac } from '../../stores/platform.js';

  export let disallowedApps = [];
  export let tunnels = [];
  export let error = '';

  const dispatch = createEventDispatcher();

  let showProcessPicker = false;
  let pickerIndex = -1;

  $: placeholder = $isMac ? 'chrome, /Applications/Games/*' : 'chrome.exe, C:\\Games\\*';

  function add() { dispatch('add'); }
  function remove(index) { dispatch('remove', index); }
  function markDirty() { dispatch('dirty'); }

  function openProcessPicker(index) {
    pickerIndex = index;
    showProcessPicker = true;
  }

  function selectProcess(proc) {
    if (pickerIndex >= 0 && pickerIndex < disallowedApps.length) {
      dispatch('updatePattern', { index: pickerIndex, pattern: proc.name });
    }
    showProcessPicker = false;
    pickerIndex = -1;
  }

  function selectFolder(detail) {
    if (pickerIndex >= 0 && pickerIndex < disallowedApps.length) {
      dispatch('updatePattern', { index: pickerIndex, pattern: detail.pattern });
    }
    showProcessPicker = false;
    pickerIndex = -1;
  }

  function closeProcessPicker() {
    showProcessPicker = false;
    pickerIndex = -1;
  }
</script>

<div class="p-4 space-y-4">
  <div class="flex items-center justify-between">
    <div>
      <h2 class="text-lg font-semibold text-zinc-100">{$t('rules.appExclusions')}</h2>
      <p class="text-xs text-zinc-500 mt-0.5">{$t('rules.appExclusionsHint')}</p>
    </div>
    <button
      class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
      on:click={add}
    >
      {$t('rules.addBtn')}
    </button>
  </div>

  {#if error}
    <ErrorAlert message={error} />
  {/if}

  {#if disallowedApps.length === 0}
    <EmptyState title={$t('rules.noAppExclusions')} description={$t('rules.noAppExclusionsHint')}>
      <svelte:fragment slot="icon">
        <svg class="w-10 h-10 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
          <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
        </svg>
      </svelte:fragment>
    </EmptyState>
  {:else}
    <div class="space-y-2">
      {#each disallowedApps as entry, i}
        <div class="flex items-center gap-2">
          <div class="flex-1 flex gap-1.5">
            <input
              type="text"
              bind:value={entry.pattern}
              on:input={markDirty}
              placeholder={placeholder}
              class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 font-mono"
            />
            <button
              class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
              title={$t('rules.selectProcess')}
              on:click={() => openProcessPicker(i)}
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
              </svg>
            </button>
          </div>
          <select
            bind:value={entry.scope}
            on:change={markDirty}
            class="w-44 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="__global__">{$t('rules.global')}</option>
            {#each tunnels as t}
              <option value={t.id}>{t.name || t.id}</option>
            {/each}
          </select>
          <button
            class="p-1.5 text-zinc-500 hover:text-red-400 transition-colors"
            on:click={() => remove(i)}
          >
            <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
            </svg>
          </button>
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Process picker modal -->
<Modal open={showProcessPicker} title={$t('rules.selectProcess')} on:close={closeProcessPicker}>
  <div class="max-h-[50vh] overflow-y-auto">
    <ProcessPicker groupByFolder on:select={e => selectProcess(e.detail)} on:selectFolder={e => selectFolder(e.detail)} />
  </div>
  <svelte:fragment slot="footer">
    <button
      class="px-3 py-1.5 text-xs rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
      on:click={closeProcessPicker}
    >
      {$t('rules.close')}
    </button>
  </svelte:fragment>
</Modal>

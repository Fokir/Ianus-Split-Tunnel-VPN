<script>
  import { createEventDispatcher } from 'svelte';
  import ErrorAlert from '../../ErrorAlert.svelte';
  import { EmptyState } from '../../components';
  import { t } from '../../i18n';

  export let disallowedIps = [];
  export let tunnels = [];
  export let error = '';

  const dispatch = createEventDispatcher();

  function add() { dispatch('add'); }
  function remove(index) { dispatch('remove', index); }
  function markDirty() { dispatch('dirty'); }

  function handleCidrInput(e, index) {
    const filtered = e.target.value.replace(/[^0-9./]/g, '');
    e.target.value = filtered;
    dispatch('cidrInput', { index, value: filtered });
  }

  function isValidCidr(value) {
    if (!value) return true;
    const parts = value.split('/');
    if (parts.length > 2) return false;
    const ip = parts[0];
    const octets = ip.split('.');
    if (octets.length !== 4) return false;
    for (const o of octets) {
      if (!o || o.length > 3) return false;
      const n = parseInt(o, 10);
      if (isNaN(n) || n < 0 || n > 255) return false;
      if (o.length > 1 && o[0] === '0') return false;
    }
    if (parts.length === 2) {
      const prefix = parts[1];
      if (!prefix) return false;
      const p = parseInt(prefix, 10);
      if (isNaN(p) || p < 0 || p > 32) return false;
    }
    return true;
  }
</script>

<div class="p-4 space-y-4">
  <div class="flex items-center justify-between">
    <div>
      <h2 class="text-lg font-semibold text-zinc-100">{$t('rules.ipExclusions')}</h2>
      <p class="text-xs text-zinc-500 mt-0.5">{$t('rules.ipExclusionsHint')}</p>
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

  {#if disallowedIps.length === 0}
    <EmptyState title={$t('rules.noIpExclusions')} description={$t('rules.noIpExclusionsHint')}>
      <svelte:fragment slot="icon">
        <svg class="w-10 h-10 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9A7.902 7.902 0 014 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1A7.902 7.902 0 0120 12c0 4.42-3.58 8-8 8z"/>
        </svg>
      </svelte:fragment>
    </EmptyState>
  {:else}
    <div class="space-y-2">
      {#each disallowedIps as entry, i}
        <div class="flex items-center gap-2">
          <input
            type="text"
            value={entry.cidr}
            on:input={e => handleCidrInput(e, i)}
            placeholder="192.168.1.0/24"
            class="flex-1 px-3 py-2 text-sm bg-zinc-900 border rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none font-mono {entry.cidr && !isValidCidr(entry.cidr) ? 'border-red-500/60 focus:border-red-500/80' : 'border-zinc-700 focus:border-blue-500/50'}"
          />
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

<script>
  import { onMount } from 'svelte';
  import * as api from '../api.js';
  import ErrorAlert from '../ErrorAlert.svelte';
  import { Spinner, EmptyState, Modal } from '../components';
  import { t } from '../i18n';

  let subscriptions = [];
  let loading = true;
  let error = '';

  // Add/Edit modal state
  let showAddModal = false;
  let editMode = false;
  let addName = '';
  let addUrl = '';
  let addRefreshInterval = '6h';
  let addUserAgent = '';
  let addPrefix = '';
  let addSaving = false;
  let addModalError = '';

  // Refresh state
  let refreshingName = '';
  let refreshingAll = false;

  onMount(async () => {
    await refresh();
  });

  async function refresh() {
    loading = true;
    error = '';
    try {
      subscriptions = await api.listSubscriptions() || [];
    } catch (e) {
      error = e.message || $t('subscriptions.failedToLoad');
    } finally {
      loading = false;
    }
  }

  function openAddModal() {
    editMode = false;
    addName = '';
    addUrl = '';
    addRefreshInterval = '6h';
    addUserAgent = '';
    addPrefix = '';
    addSaving = false;
    addModalError = '';
    showAddModal = true;
  }

  function openEditModal(sub) {
    editMode = true;
    addName = sub.name;
    addUrl = sub.url;
    addRefreshInterval = sub.refreshInterval || '';
    addUserAgent = sub.userAgent || '';
    addPrefix = sub.prefix || '';
    addSaving = false;
    addModalError = '';
    showAddModal = true;
  }

  function closeAddModal() {
    showAddModal = false;
  }

  async function saveSubscription() {
    if (!addName.trim()) { addModalError = $t('subscriptions.nameRequired'); return; }
    if (!addUrl.trim()) { addModalError = $t('subscriptions.urlRequired'); return; }
    addSaving = true;
    addModalError = '';
    try {
      if (editMode) {
        await api.updateSubscription({
          name: addName.trim(),
          url: addUrl.trim(),
          refreshInterval: addRefreshInterval.trim(),
          userAgent: addUserAgent.trim(),
          prefix: addPrefix.trim(),
        });
      } else {
        await api.addSubscription({
          name: addName.trim(),
          url: addUrl.trim(),
          refreshInterval: addRefreshInterval.trim(),
          userAgent: addUserAgent.trim(),
          prefix: addPrefix.trim(),
        });
      }
      showAddModal = false;
      await refresh();
    } catch (e) {
      addModalError = e.message;
    } finally {
      addSaving = false;
    }
  }

  async function removeSub(name) {
    error = '';
    try {
      await api.removeSubscription(name);
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function refreshSub(name) {
    refreshingName = name;
    error = '';
    try {
      await api.refreshSubscription(name);
      await refresh();
    } catch (e) {
      error = e.message;
    } finally {
      refreshingName = '';
    }
  }

  async function refreshAll() {
    refreshingAll = true;
    error = '';
    try {
      await api.refreshAllSubscriptions();
      await refresh();
    } catch (e) {
      error = e.message;
    } finally {
      refreshingAll = false;
    }
  }
</script>

<div class="p-4 space-y-4">
  <!-- Header -->
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">{$t('subscriptions.title')}</h2>
    <div class="flex items-center gap-2">
      {#if subscriptions.length > 0}
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-green-600/20 text-green-400 hover:bg-green-600/30 transition-colors disabled:opacity-50"
          disabled={refreshingAll}
          on:click={refreshAll}
        >
          {refreshingAll ? $t('subscriptions.refreshing') : $t('subscriptions.refreshAll')}
        </button>
      {/if}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
        on:click={openAddModal}
      >
        {$t('subscriptions.add')}
      </button>
    </div>
  </div>

  <!-- Error -->
  {#if error}
    <ErrorAlert message={error} />
  {/if}

  <!-- Loading -->
  {#if loading}
    <div class="py-12">
      <Spinner text={$t('subscriptions.loading')} />
    </div>
  {:else if subscriptions.length === 0}
    <EmptyState title={$t('subscriptions.emptyTitle')} description={$t('subscriptions.emptyHint')}>
      <svg slot="icon" class="w-12 h-12" viewBox="0 0 24 24" fill="currentColor">
        <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z"/>
      </svg>
    </EmptyState>
  {:else}
    <!-- Subscription list -->
    <div class="space-y-2">
      {#each subscriptions as sub}
        <div class="p-3 bg-zinc-800/50 border border-zinc-700/40 rounded-lg hover:bg-zinc-800/70 transition-colors">
          <div class="flex items-center justify-between">
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="text-sm font-medium text-zinc-200">{sub.name}</span>
                {#if sub.tunnelCount > 0}
                  <span class="px-1.5 py-0.5 text-xs rounded bg-green-600/20 text-green-400">{sub.tunnelCount} {sub.tunnelCount === 1 ? $t('subscriptions.tunnel') : $t('subscriptions.tunnels')}</span>
                {/if}
                {#if sub.lastError}
                  <span class="px-1.5 py-0.5 text-xs rounded bg-red-600/20 text-red-400">{$t('subscriptions.error')}</span>
                {/if}
              </div>
              <div class="text-xs text-zinc-500 mt-0.5 truncate" title={sub.url}>{sub.url}</div>
              <div class="flex items-center gap-3 text-xs text-zinc-500 mt-0.5">
                {#if sub.refreshInterval}
                  <span>refresh: {sub.refreshInterval}</span>
                {/if}
                {#if sub.prefix}
                  <span>prefix: {sub.prefix}</span>
                {/if}
              </div>
              {#if sub.lastError}
                <div class="text-xs text-red-400 mt-1">{sub.lastError}</div>
              {/if}
            </div>

            <div class="flex items-center gap-1 shrink-0 ml-3">
              <!-- Edit button -->
              <button
                class="p-1.5 rounded-md text-zinc-400 hover:text-blue-400 hover:bg-zinc-700/50 transition-colors"
                title={$t('subscriptions.edit')}
                on:click={() => openEditModal(sub)}
              >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a.996.996 0 000-1.41l-2.34-2.34a.996.996 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/>
                </svg>
              </button>
              <!-- Refresh button -->
              <button
                class="p-1.5 rounded-md text-zinc-400 hover:text-green-400 hover:bg-zinc-700/50 transition-colors disabled:opacity-50"
                title={$t('subscriptions.refresh')}
                disabled={refreshingName === sub.name}
                on:click={() => refreshSub(sub.name)}
              >
                <svg class="w-4 h-4 {refreshingName === sub.name ? 'animate-spin' : ''}" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
                </svg>
              </button>
              <!-- Remove button -->
              <button
                class="p-1.5 rounded-md text-zinc-400 hover:text-red-400 hover:bg-zinc-700/50 transition-colors"
                title={$t('subscriptions.remove')}
                on:click={() => removeSub(sub.name)}
              >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
                </svg>
              </button>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Info block -->
  <div class="px-3 py-2 text-xs bg-zinc-800/50 border border-zinc-700/30 rounded-lg text-zinc-500">
    {$t('subscriptions.info')}
  </div>
</div>

<!-- Add subscription modal -->
<Modal open={showAddModal} title={editMode ? $t('subscriptions.editTitle') : $t('subscriptions.addTitle')} on:close={closeAddModal}>
      <div class="space-y-3">
        {#if addModalError}
          <ErrorAlert message={addModalError} />
        {/if}
        <div>
          <label for="sub-name" class="block text-xs font-medium text-zinc-400 mb-1">{$t('subscriptions.nameLabel')}</label>
          <input id="sub-name" type="text" bind:value={addName} placeholder="my-provider" disabled={editMode}
            class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed" />
        </div>
        <div>
          <label for="sub-url" class="block text-xs font-medium text-zinc-400 mb-1">{$t('subscriptions.urlLabel')}</label>
          <input id="sub-url" type="text" bind:value={addUrl} placeholder="https://panel.example.com/api/v1/client/subscribe?token=..."
            class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono text-xs focus:border-blue-500 focus:outline-none" />
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label for="sub-interval" class="block text-xs font-medium text-zinc-400 mb-1">{$t('subscriptions.refreshInterval')}</label>
            <select id="sub-interval" bind:value={addRefreshInterval}
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
              <option value="">{$t('subscriptions.refreshNone')}</option>
              <option value="1h">{$t('subscriptions.hour1')}</option>
              <option value="6h">{$t('subscriptions.hour6')}</option>
              <option value="12h">{$t('subscriptions.hour12')}</option>
              <option value="24h">{$t('subscriptions.hour24')}</option>
            </select>
          </div>
          <div>
            <label for="sub-prefix" class="block text-xs font-medium text-zinc-400 mb-1">{$t('subscriptions.prefix')}</label>
            <input id="sub-prefix" type="text" bind:value={addPrefix} placeholder={$t('subscriptions.prefixPlaceholder')}
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
          </div>
        </div>
        <div>
          <label for="sub-ua" class="block text-xs font-medium text-zinc-400 mb-1">{$t('subscriptions.userAgent')}</label>
          <input id="sub-ua" type="text" bind:value={addUserAgent} placeholder="ClashForWindows/0.20.39"
            class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
        </div>
      </div>

      <svelte:fragment slot="footer">
        <button
          class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
          on:click={closeAddModal}
        >
          {$t('subscriptions.cancel')}
        </button>
        <button
          class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          disabled={addSaving || !addName.trim() || !addUrl.trim()}
          on:click={saveSubscription}
        >
          {addSaving ? $t('subscriptions.savingBtn') : (editMode ? $t('subscriptions.saveBtn') : $t('subscriptions.addRefresh'))}
        </button>
      </svelte:fragment>
</Modal>

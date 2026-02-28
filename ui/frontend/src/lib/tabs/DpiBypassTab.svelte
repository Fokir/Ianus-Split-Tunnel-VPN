<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import * as api from '../api.js';
  import ErrorAlert from '../ErrorAlert.svelte';
  import { t } from '../i18n';

  let error = '';
  let loading = true;

  // ─── DPI enabled state ───────────────────────────────────────────
  let dpiEnabled = false;
  let toggling = false;

  // ─── Strategies ──────────────────────────────────────────────────
  let strategies = [];
  let selectedStrategy = null;
  let refreshing = false;

  // ─── Parameters form (from selected strategy's ops[0]) ──────────
  let formMode = 'none';
  let formSplitPos = '';
  let formFakeTtl = 1;
  let formFool = [];
  let formRepeats = 1;
  let formSplitSeqOvl = 0;
  let formFilterPorts = '80, 443';
  let formCutoff = '';
  let saving = false;

  const desyncModes = ['none', 'fake', 'multisplit', 'fakedsplit', 'multidisorder'];
  const foolMethods = ['ttl', 'badseq', 'badsum', 'md5sig'];

  // ─── Search ──────────────────────────────────────────────────────
  let searching = false;
  let searchProgress = null;

  // ─── Probe ───────────────────────────────────────────────────────
  let testDomain = 'youtube.com';
  let probingStrategy = null;
  let probeResults = {};

  // ─── Load data ───────────────────────────────────────────────────
  async function loadData() {
    loading = true;
    error = '';
    try {
      const [cfg, strats] = await Promise.all([
        api.getDPIConfig(),
        api.listDPIStrategies().catch(() => []),
      ]);
      dpiEnabled = cfg?.enabled || false;
      strategies = sortStrategies(strats || []);
    } catch (e) {
      error = e.message || 'Failed to load DPI config';
    } finally {
      loading = false;
    }
  }

  function sortStrategies(list) {
    const order = { search: 0, zapret: 1, user: 2 };
    return [...list].sort((a, b) => (order[a.source] ?? 9) - (order[b.source] ?? 9));
  }

  onMount(() => {
    loadData();
    Events.On('dpi-search-progress', handleSearchProgress);
  });

  onDestroy(() => {
    Events.Off('dpi-search-progress', handleSearchProgress);
  });

  // ─── Toggle DPI ──────────────────────────────────────────────────
  async function toggleDPI() {
    toggling = true;
    error = '';
    try {
      await api.setDPIEnabled(!dpiEnabled);
      dpiEnabled = !dpiEnabled;
      if (dpiEnabled) {
        // Reload strategies after enabling.
        const strats = await api.listDPIStrategies().catch(() => []);
        strategies = sortStrategies(strats);
      }
    } catch (e) {
      error = e.message || 'Failed to toggle DPI';
    } finally {
      toggling = false;
    }
  }

  // ─── Refresh strategies ──────────────────────────────────────────
  async function refreshStrategies() {
    refreshing = true;
    error = '';
    try {
      const strats = await api.fetchDPIStrategies();
      strategies = sortStrategies(strats || []);
    } catch (e) {
      error = e.message || $t('dpiBypass.refreshError');
    } finally {
      refreshing = false;
    }
  }

  // ─── Select strategy ────────────────────────────────────────────
  function selectStrategy(strategy) {
    selectedStrategy = strategy.name;
    // Populate form from ops[0]
    const op = strategy.ops?.[0];
    if (op) {
      formMode = op.mode || 'none';
      formSplitPos = (op.splitPos || []).join(', ');
      formFakeTtl = op.fakeTtl || 1;
      formFool = [...(op.fool || [])];
      formRepeats = op.repeats || 1;
      formSplitSeqOvl = op.splitSeqOvl || 0;
      formFilterPorts = (op.filterPorts || []).join(', ');
      formCutoff = op.cutoff || '';
    } else {
      resetForm();
    }
  }

  function resetForm() {
    formMode = 'none';
    formSplitPos = '';
    formFakeTtl = 1;
    formFool = [];
    formRepeats = 1;
    formSplitSeqOvl = 0;
    formFilterPorts = '80, 443';
    formCutoff = '';
  }

  // ─── Save / activate strategy ────────────────────────────────────
  async function saveStrategy() {
    if (!selectedStrategy) return;
    saving = true;
    error = '';
    try {
      await api.selectDPIStrategy(selectedStrategy);
    } catch (e) {
      error = e.message || 'Failed to save strategy';
    } finally {
      saving = false;
    }
  }

  // ─── Toggle fool method ─────────────────────────────────────────
  function toggleFool(method) {
    if (formFool.includes(method)) {
      formFool = formFool.filter(f => f !== method);
    } else {
      formFool = [...formFool, method];
    }
  }

  // ─── Search ──────────────────────────────────────────────────────
  async function toggleSearch() {
    error = '';
    if (searching) {
      try {
        await api.stopDPISearch();
      } catch (e) {
        error = e.message;
      }
      searching = false;
    } else {
      try {
        await api.startDPISearchStream();
        await api.startDPISearch(selectedStrategy || '');
        searching = true;
        searchProgress = null;
      } catch (e) {
        error = e.message || 'Failed to start search';
      }
    }
  }

  function handleSearchProgress(event) {
    const data = event.data?.[0] || event.data || event;
    searchProgress = data;
    if (data.complete) {
      searching = false;
      if (data.found) {
        // Reload strategies to pick up the new one.
        api.listDPIStrategies().then(strats => {
          strategies = sortStrategies(strats || []);
        }).catch(() => {});
      }
    }
  }

  // ─── Probe ───────────────────────────────────────────────────────
  async function probeStrategy(strategyName) {
    if (!testDomain) return;
    probingStrategy = strategyName;
    probeResults = { ...probeResults, [strategyName]: null };
    try {
      const result = await api.probeDPI(testDomain, strategyName);
      probeResults = {
        ...probeResults,
        [strategyName]: result,
      };
    } catch (e) {
      probeResults = {
        ...probeResults,
        [strategyName]: { success: false, error: e.message },
      };
    } finally {
      probingStrategy = null;
    }
  }

  // ─── Source badge ────────────────────────────────────────────────
  function sourceBadgeClass(source) {
    switch (source) {
      case 'search': return 'bg-green-600/20 text-green-400 border-green-600/30';
      case 'zapret': return 'bg-blue-600/20 text-blue-400 border-blue-600/30';
      case 'user':   return 'bg-zinc-600/20 text-zinc-400 border-zinc-600/30';
      default:       return 'bg-zinc-600/20 text-zinc-400 border-zinc-600/30';
    }
  }

  function sourceLabel(source) {
    switch (source) {
      case 'search': return $t('dpiBypass.sourceAuto');
      case 'zapret': return $t('dpiBypass.sourceZapret');
      case 'user':   return $t('dpiBypass.sourceUser');
      default:       return source;
    }
  }
</script>

<div class="p-4 space-y-6">
  <h2 class="text-lg font-semibold text-zinc-100">{$t('dpiBypass.title')}</h2>

  {#if error}
    <ErrorAlert message={error} />
  {/if}

  {#if loading}
    <div class="flex items-center justify-center py-12 text-zinc-500">
      <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24" fill="none">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
      </svg>
    </div>
  {:else}
    <!-- Section 1: Enable/Disable toggle -->
    <section class="space-y-3">
      <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4">
        <!-- svelte-ignore a11y-label-has-associated-control -->
        <label class="flex items-center justify-between cursor-pointer">
          <div>
            <div class="text-sm text-zinc-200">{$t('dpiBypass.enabled')}</div>
            <div class="text-xs text-zinc-500">{$t('dpiBypass.enabledHint')}</div>
          </div>
          {#if toggling}
            <div class="flex items-center gap-2 text-xs text-zinc-400">
              <svg class="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
              </svg>
              {dpiEnabled ? $t('dpiBypass.disabling') : $t('dpiBypass.enabling')}
            </div>
          {:else}
            <input
              type="checkbox"
              checked={dpiEnabled}
              on:change={toggleDPI}
              class="w-9 h-5 bg-zinc-700 rounded-full appearance-none relative cursor-pointer
                     checked:bg-blue-600 transition-colors
                     after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4
                     after:bg-white after:rounded-full after:transition-transform
                     checked:after:translate-x-4"
            />
          {/if}
        </label>
      </div>
    </section>

    {#if dpiEnabled}
      <!-- Test domain input -->
      <section class="space-y-2">
        <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4">
          <label for="test-domain" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.testDomain')}</label>
          <p class="text-xs text-zinc-500 mb-2">{$t('dpiBypass.testDomainHint')}</p>
          <input
            id="test-domain"
            type="text"
            bind:value={testDomain}
            placeholder="youtube.com"
            class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
          />
        </div>
      </section>

      <!-- Section 2: Strategies list -->
      <section class="space-y-3">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">{$t('dpiBypass.strategies')}</h3>
          <button
            class="px-2.5 py-1 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors disabled:opacity-40"
            on:click={refreshStrategies}
            disabled={refreshing}
          >
            {#if refreshing}
              <svg class="inline-block animate-spin h-3 w-3 mr-1" viewBox="0 0 24 24" fill="none">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
              </svg>
              {$t('dpiBypass.refreshing')}
            {:else}
              <svg class="inline-block h-3 w-3 mr-1" viewBox="0 0 24 24" fill="currentColor">
                <path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
              </svg>
              {$t('dpiBypass.refresh')}
            {/if}
          </button>
        </div>

        <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg overflow-hidden">
          {#if strategies.length === 0}
            <div class="p-6 text-center">
              <p class="text-sm text-zinc-400">{$t('dpiBypass.noStrategies')}</p>
              <p class="text-xs text-zinc-500 mt-1">{$t('dpiBypass.noStrategiesHint')}</p>
            </div>
          {:else}
            <div class="divide-y divide-zinc-700/30 max-h-60 overflow-y-auto">
              {#each strategies as strategy}
                <button
                  class="w-full flex items-center justify-between px-4 py-2.5 text-left transition-colors
                         {selectedStrategy === strategy.name
                           ? 'bg-blue-600/20 border-l-2 border-l-blue-500'
                           : 'hover:bg-zinc-800/60 border-l-2 border-l-transparent'}"
                  on:click={() => selectStrategy(strategy)}
                >
                  <div class="flex items-center gap-2 min-w-0">
                    <span class="text-sm text-zinc-200 truncate">{strategy.name}</span>
                    <span class="inline-flex px-1.5 py-0.5 text-[10px] font-medium rounded border {sourceBadgeClass(strategy.source)}">
                      {sourceLabel(strategy.source)}
                    </span>
                  </div>
                  <div class="flex items-center gap-2 shrink-0">
                    {#if probeResults[strategy.name] !== undefined}
                      {#if probeResults[strategy.name] === null}
                        <svg class="animate-spin h-3.5 w-3.5 text-zinc-400" viewBox="0 0 24 24" fill="none">
                          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                      {:else if probeResults[strategy.name].success}
                        <span class="text-[10px] text-green-400">{probeResults[strategy.name].latencyMs}ms</span>
                      {:else}
                        <span class="text-[10px] text-red-400">{$t('dpiBypass.probeFailed')}</span>
                      {/if}
                    {/if}
                    <button
                      class="px-2 py-0.5 text-[10px] font-medium rounded bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200 transition-colors"
                      on:click|stopPropagation={() => probeStrategy(strategy.name)}
                      disabled={probingStrategy === strategy.name}
                    >
                      {probingStrategy === strategy.name ? $t('dpiBypass.probing') : $t('dpiBypass.probe')}
                    </button>
                  </div>
                </button>
              {/each}
            </div>
          {/if}
        </div>
      </section>

      <!-- Section 3: Parameters form -->
      {#if selectedStrategy}
        <section class="space-y-3">
          <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">{$t('dpiBypass.parameters')}</h3>
          <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4 space-y-3">
            <!-- Mode -->
            <div>
              <label for="dpi-mode" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.mode')}</label>
              <select
                id="dpi-mode"
                bind:value={formMode}
                class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
              >
                {#each desyncModes as mode}
                  <option value={mode}>{mode}</option>
                {/each}
              </select>
            </div>

            <div class="grid grid-cols-2 gap-3">
              <!-- Split Pos -->
              <div>
                <label for="dpi-split-pos" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.splitPos')}</label>
                <input
                  id="dpi-split-pos"
                  type="text"
                  bind:value={formSplitPos}
                  placeholder="1, 0"
                  class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
                />
                <p class="text-[10px] text-zinc-500 mt-0.5">{$t('dpiBypass.splitPosHint')}</p>
              </div>

              <!-- Fake TTL -->
              <div>
                <label for="dpi-fake-ttl" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.fakeTtl')}</label>
                <input
                  id="dpi-fake-ttl"
                  type="number"
                  bind:value={formFakeTtl}
                  min="1"
                  max="255"
                  class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
                />
              </div>
            </div>

            <!-- Fool methods -->
            <div>
              <!-- svelte-ignore a11y-label-has-associated-control -->
              <span class="block text-xs font-medium text-zinc-400 mb-1.5">{$t('dpiBypass.fool')}</span>
              <div class="flex flex-wrap gap-1.5">
                {#each foolMethods as method}
                  <button
                    class="px-2.5 py-1 text-xs rounded-md border transition-colors
                           {formFool.includes(method)
                             ? 'bg-blue-600/20 border-blue-500/50 text-blue-400'
                             : 'bg-zinc-900 border-zinc-700 text-zinc-400 hover:border-zinc-600'}"
                    on:click={() => toggleFool(method)}
                  >
                    {method}
                  </button>
                {/each}
              </div>
            </div>

            <div class="grid grid-cols-3 gap-3">
              <!-- Repeats -->
              <div>
                <label for="dpi-repeats" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.repeats')}</label>
                <input
                  id="dpi-repeats"
                  type="number"
                  bind:value={formRepeats}
                  min="1"
                  max="20"
                  class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
                />
              </div>

              <!-- Split Seq Ovl -->
              <div>
                <label for="dpi-seq-ovl" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.splitSeqOvl')}</label>
                <input
                  id="dpi-seq-ovl"
                  type="number"
                  bind:value={formSplitSeqOvl}
                  class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
                />
              </div>

              <!-- Cutoff -->
              <div>
                <label for="dpi-cutoff" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.cutoff')}</label>
                <input
                  id="dpi-cutoff"
                  type="text"
                  bind:value={formCutoff}
                  class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
                />
              </div>
            </div>

            <!-- Filter Ports -->
            <div>
              <label for="dpi-ports" class="block text-xs font-medium text-zinc-400 mb-1">{$t('dpiBypass.filterPorts')}</label>
              <input
                id="dpi-ports"
                type="text"
                bind:value={formFilterPorts}
                placeholder="80, 443"
                class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
              />
              <p class="text-[10px] text-zinc-500 mt-0.5">{$t('dpiBypass.filterPortsHint')}</p>
            </div>

            <!-- Save button -->
            <div class="flex justify-end pt-2">
              <button
                class="px-4 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
                on:click={saveStrategy}
                disabled={saving || !selectedStrategy}
              >
                {saving ? $t('dpiBypass.saving') : $t('dpiBypass.save')}
              </button>
            </div>
          </div>
        </section>
      {/if}

      <!-- Section 4: Auto-search -->
      <section class="space-y-3">
        <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">{$t('dpiBypass.search')}</h3>
        <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4 space-y-3">
          <button
            class="px-4 py-2 text-sm font-medium rounded-lg transition-colors
                   {searching
                     ? 'bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30'
                     : 'bg-blue-600 text-white hover:bg-blue-500'}"
            on:click={toggleSearch}
          >
            {#if searching}
              <svg class="inline-block h-3.5 w-3.5 mr-1.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M6 6h12v12H6z"/>
              </svg>
              {$t('dpiBypass.stopSearch')}
            {:else}
              <svg class="inline-block h-3.5 w-3.5 mr-1.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M8 5v14l11-7z"/>
              </svg>
              {$t('dpiBypass.startSearch')}
            {/if}
          </button>

          {#if searchProgress}
            <div class="space-y-2">
              {#if !searchProgress.complete}
                <!-- Progress bar -->
                <div class="space-y-1">
                  <div class="flex items-center justify-between text-xs text-zinc-400">
                    <span>{$t('dpiBypass.searchPhase').replace('{phase}', searchProgress.phase)}</span>
                    <span>{$t('dpiBypass.searchProgress').replace('{tested}', searchProgress.tested).replace('{total}', searchProgress.total)}</span>
                  </div>
                  <div class="h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                    <div
                      class="h-full bg-blue-500 rounded-full transition-all duration-300"
                      style="width: {searchProgress.total > 0 ? Math.round((searchProgress.tested / searchProgress.total) * 100) : 0}%"
                    ></div>
                  </div>
                  {#if searchProgress.currentDesc}
                    <p class="text-[10px] text-zinc-500 truncate">{searchProgress.currentDesc}</p>
                  {/if}
                </div>
              {:else if searchProgress.found}
                <!-- Found -->
                <div class="flex items-center gap-2 px-3 py-2 bg-green-900/20 border border-green-800/40 rounded-lg">
                  <svg class="h-4 w-4 text-green-400 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/>
                  </svg>
                  <span class="text-sm text-green-300">{$t('dpiBypass.searchFound').replace('{name}', searchProgress.strategyName)}</span>
                </div>
              {:else if searchProgress.error}
                <!-- Error -->
                <div class="px-3 py-2 bg-red-900/20 border border-red-800/40 rounded-lg">
                  <span class="text-sm text-red-300">{$t('dpiBypass.searchError').replace('{error}', searchProgress.error)}</span>
                </div>
              {:else}
                <!-- Not found -->
                <div class="px-3 py-2 bg-zinc-800/60 border border-zinc-700/40 rounded-lg">
                  <span class="text-sm text-zinc-400">{$t('dpiBypass.searchNotFound')}</span>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      </section>
    {/if}
  {/if}
</div>

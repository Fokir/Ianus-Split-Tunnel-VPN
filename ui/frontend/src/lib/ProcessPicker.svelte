<script>
  /**
   * ProcessPicker — shared component for selecting a running process.
   *
   * Features:
   *   - Loads enriched process list (icons, window detection) from the API
   *   - Client-side search by name or path
   *   - Categorised: windowed apps first, then background processes
   *   - Icons for windowed processes
   *   - Optional folder grouping with collapsible sections
   *   - Folder select button for path/* patterns
   *
   * Props:
   *   compact        — smaller max-height for inline embedding (default: false)
   *   groupByFolder  — group processes by parent folder (default: false)
   *
   * Events:
   *   select       — fires with the chosen process object ({ name, path, icon, ... })
   *   selectFolder — fires with { folder, pattern } for folder-based pattern selection
   */
  import { createEventDispatcher, onMount } from 'svelte';
  import * as api from './api.js';
  import { t } from './i18n';
  import { isMac } from './stores/platform.js';

  export let compact = false;
  export let groupByFolder = false;

  const dispatch = createEventDispatcher();

  let allProcesses = [];
  let filter = '';
  let loading = false;
  let loadError = '';

  $: filtered = allProcesses.filter(p =>
    !filter ||
    p.name.toLowerCase().includes(filter.toLowerCase()) ||
    (p.path && p.path.toLowerCase().includes(filter.toLowerCase()))
  );

  $: windowedProcs = filtered.filter(p => p.hasWindow);
  $: backgroundProcs = filtered.filter(p => !p.hasWindow);

  // ─── Folder Grouping ─────────────────────────────────────────────

  function extractFolder(path) {
    if (!path) return '';
    // macOS: group by .app bundle
    if ($isMac) {
      const appIdx = path.toLowerCase().indexOf('.app/');
      if (appIdx >= 0) return path.substring(0, appIdx + 4);
    }
    // General: parent directory
    const lastSep = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
    return lastSep > 0 ? path.substring(0, lastSep) : '';
  }

  function folderDisplayName(folder) {
    if (!folder) return 'Unknown';
    const lastSep = Math.max(folder.lastIndexOf('/'), folder.lastIndexOf('\\'));
    return lastSep >= 0 ? folder.substring(lastSep + 1) : folder;
  }

  function folderPattern(folder) {
    if (!folder) return '';
    return folder.replace(/[\\/]+$/, '') + '/*';
  }

  function selectFolder(folder) {
    dispatch('selectFolder', { folder, pattern: folderPattern(folder) });
  }

  $: folderGroups = groupByFolder ? computeFolderGroups(filtered) : [];

  function computeFolderGroups(procs) {
    const map = new Map();
    for (const proc of procs) {
      const folder = extractFolder(proc.path);
      const key = folder.toLowerCase() || '__no_path__';
      if (!map.has(key)) map.set(key, { folder, displayName: folderDisplayName(folder), procs: [] });
      map.get(key).procs.push(proc);
    }
    const groups = Array.from(map.values());
    groups.sort((a, b) => {
      const aW = a.procs.some(p => p.hasWindow), bW = b.procs.some(p => p.hasWindow);
      if (aW !== bW) return bW ? 1 : -1;
      return a.displayName.localeCompare(b.displayName);
    });
    return groups;
  }

  let collapsedFolders = new Set();
  function toggleFolder(key) {
    collapsedFolders.has(key) ? collapsedFolders.delete(key) : collapsedFolders.add(key);
    collapsedFolders = new Set(collapsedFolders);
  }

  // ─── Lifecycle ────────────────────────────────────────────────────

  onMount(loadProcesses);

  async function loadProcesses() {
    loading = true;
    loadError = '';
    try {
      allProcesses = await api.listProcesses('') || [];
    } catch (e) {
      allProcesses = [];
      loadError = e?.message || String(e);
    } finally {
      loading = false;
    }
  }

  function select(proc) {
    dispatch('select', proc);
  }
</script>

<div class="space-y-2 {compact ? 'max-h-52' : ''} {compact ? 'overflow-y-auto' : ''}">
  <!-- Search -->
  <input
    type="text"
    bind:value={filter}
    placeholder={$t('rules.searchProcess')}
    class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
  />

  <!-- List -->
  <div class="{compact ? '' : 'space-y-3'}">
    {#if loading}
      <div class="flex items-center justify-center py-6 text-zinc-500">
        <svg class="animate-spin h-4 w-4 mr-2" viewBox="0 0 24 24" fill="none">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        {$t('rules.loadingProcesses')}
      </div>
    {:else if loadError}
      <div class="py-4 text-center space-y-2">
        <div class="text-xs text-red-400">{$t('rules.processLoadError')}</div>
        <div class="text-[10px] text-zinc-600 font-mono break-all px-2">{loadError}</div>
        <button
          class="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          on:click={loadProcesses}
        >{$t('rules.retry')}</button>
      </div>
    {:else if filtered.length === 0}
      <div class="text-xs text-zinc-500 py-4 text-center">{$t('rules.noProcesses')}</div>
    {:else if groupByFolder && folderGroups.length > 0}
      <!-- Folder-grouped view -->
      {#each folderGroups as group (group.folder || '__no_path__')}
        {@const folderKey = group.folder.toLowerCase() || '__no_path__'}
        {@const isCollapsed = collapsedFolders.has(folderKey)}
        {@const groupIcon = group.procs.find(p => p.hasWindow && p.icon)}
        <div class="border border-zinc-700/30 rounded-lg overflow-hidden mb-1.5">
          <!-- Folder header -->
          <div class="bg-zinc-800/40 px-3 py-1.5 flex items-center gap-2">
            <!-- svelte-ignore a11y-click-events-have-key-events -->
            <!-- svelte-ignore a11y-no-static-element-interactions -->
            <div class="flex items-center gap-2 flex-1 min-w-0 cursor-pointer" on:click={() => toggleFolder(folderKey)}>
              <svg class="w-3 h-3 text-zinc-500 shrink-0 transition-transform {isCollapsed ? '-rotate-90' : ''}" viewBox="0 0 24 24" fill="currentColor">
                <path d="M7 10l5 5 5-5z"/>
              </svg>
              {#if groupIcon}
                <img src={groupIcon.icon} alt="" class="w-4 h-4 shrink-0 rounded" />
              {:else}
                <svg class="w-3.5 h-3.5 text-zinc-500 shrink-0" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                </svg>
              {/if}
              <span class="text-xs text-zinc-300 truncate">{group.displayName}</span>
              <span class="text-[10px] text-zinc-600 shrink-0">{group.procs.length}</span>
            </div>
            {#if group.folder}
              <button
                class="p-1 text-zinc-500 hover:text-blue-400 transition-colors shrink-0"
                title={$t('rules.selectFolder')}
                on:click|stopPropagation={() => selectFolder(group.folder)}
              >
                <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-6 10H6v-2h8v2zm4-4H6v-2h12v2z"/>
                </svg>
              </button>
            {/if}
          </div>
          <!-- Folder processes -->
          {#if !isCollapsed}
            <div class="space-y-0.5">
              {#each group.procs as proc}
                <div class="flex items-center gap-1 pl-8 pr-2">
                  <button
                    class="flex-1 flex items-center gap-3 px-2 {compact ? 'py-1' : 'py-1.5'} rounded-lg hover:bg-zinc-700/50 transition-colors text-left min-w-0"
                    on:click={() => select(proc)}
                  >
                    <div class="{compact ? 'w-5 h-5' : 'w-6 h-6'} shrink-0 flex items-center justify-center rounded bg-zinc-700/50">
                      {#if proc.icon}
                        <img src={proc.icon} alt="" class="{compact ? 'w-4 h-4' : 'w-5 h-5'}" />
                      {:else if proc.hasWindow}
                        <svg class="w-3.5 h-3.5 text-zinc-500" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                        </svg>
                      {:else}
                        <svg class="w-3.5 h-3.5 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
                          <path d="M17 7h-4v2h4c1.65 0 3 1.35 3 3s-1.35 3-3 3h-4v2h4c2.76 0 5-2.24 5-5s-2.24-5-5-5zm-6 8H7c-1.65 0-3-1.35-3-3s1.35-3 3-3h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-2zm-3-4h8v2H8z"/>
                        </svg>
                      {/if}
                    </div>
                    <div class="min-w-0 flex-1">
                      <div class="text-sm {proc.hasWindow ? 'text-zinc-200' : 'text-zinc-300'} truncate">{proc.name}</div>
                    </div>
                  </button>
                  {#if proc.path}
                    <button
                      class="p-1 text-zinc-600 hover:text-blue-400 transition-colors shrink-0"
                      title={$t('rules.selectFolder')}
                      on:click={() => selectFolder(extractFolder(proc.path))}
                    >
                      <svg class="w-3 h-3" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                      </svg>
                    </button>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    {:else}
      <!-- Flat view (windowed + background) -->
      <!-- Windowed apps -->
      {#if windowedProcs.length > 0}
        <div>
          {#if !compact}
            <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium px-1 mb-1.5">{$t('rules.windowedApps')}</div>
          {/if}
          <div class="space-y-0.5">
            {#each windowedProcs as proc}
              <div class="flex items-center gap-1">
                <button
                  class="flex-1 flex items-center gap-3 px-3 {compact ? 'py-1.5' : 'py-2'} rounded-lg hover:bg-zinc-700/50 transition-colors text-left min-w-0"
                  on:click={() => select(proc)}
                >
                  <div class="{compact ? 'w-6 h-6' : 'w-7 h-7'} shrink-0 flex items-center justify-center rounded bg-zinc-700/50">
                    {#if proc.icon}
                      <img src={proc.icon} alt="" class="{compact ? 'w-5 h-5' : 'w-6 h-6'}" />
                    {:else}
                      <svg class="w-4 h-4 text-zinc-500" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                      </svg>
                    {/if}
                  </div>
                  <div class="min-w-0 flex-1">
                    <div class="text-sm text-zinc-200 truncate">{proc.name}</div>
                    {#if proc.path && !compact}
                      <div class="text-[10px] text-zinc-500 truncate">{proc.path}</div>
                    {/if}
                  </div>
                </button>
                {#if proc.path}
                  <button
                    class="p-1 text-zinc-600 hover:text-blue-400 transition-colors shrink-0"
                    title={$t('rules.selectFolder')}
                    on:click={() => selectFolder(extractFolder(proc.path))}
                  >
                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                    </svg>
                  </button>
                {/if}
              </div>
            {/each}
          </div>
        </div>
      {/if}

      <!-- Background processes -->
      {#if backgroundProcs.length > 0}
        <div>
          {#if !compact}
            <div class="text-[10px] uppercase tracking-wider text-zinc-500 font-medium px-1 mb-1.5">{$t('rules.backgroundProcs')}</div>
          {/if}
          <div class="space-y-0.5">
            {#each (compact ? backgroundProcs.slice(0, 50) : backgroundProcs.slice(0, 100)) as proc}
              <div class="flex items-center gap-1">
                <button
                  class="flex-1 flex items-center gap-3 px-3 {compact ? 'py-1' : 'py-1.5'} rounded-lg hover:bg-zinc-700/50 transition-colors text-left min-w-0"
                  on:click={() => select(proc)}
                >
                  <div class="{compact ? 'w-6 h-6' : 'w-7 h-7'} shrink-0 flex items-center justify-center rounded bg-zinc-700/50">
                    <svg class="w-4 h-4 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M17 7h-4v2h4c1.65 0 3 1.35 3 3s-1.35 3-3 3h-4v2h4c2.76 0 5-2.24 5-5s-2.24-5-5-5zm-6 8H7c-1.65 0-3-1.35-3-3s1.35-3 3-3h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-2zm-3-4h8v2H8z"/>
                    </svg>
                  </div>
                  <div class="min-w-0 flex-1">
                    <div class="text-sm text-zinc-300 truncate">{proc.name}</div>
                    {#if proc.path && !compact}
                      <div class="text-[10px] text-zinc-600 truncate">{proc.path}</div>
                    {/if}
                  </div>
                </button>
                {#if proc.path}
                  <button
                    class="p-1 text-zinc-600 hover:text-blue-400 transition-colors shrink-0"
                    title={$t('rules.selectFolder')}
                    on:click={() => selectFolder(extractFolder(proc.path))}
                  >
                    <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M20 6H12L10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2z"/>
                    </svg>
                  </button>
                {/if}
              </div>
            {/each}
          </div>
        </div>
      {/if}
    {/if}
  </div>
</div>

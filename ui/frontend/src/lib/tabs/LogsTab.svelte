<script>
  import { onMount, onDestroy, tick } from 'svelte';
  import { Clipboard, Dialogs, Call } from '@wailsio/runtime';
  import { logStore, maxLogsStore, ALLOWED_LIMITS } from '../stores/logs.js';
  import { t } from '../i18n';

  let autoScroll = true;
  let logsContainer;
  let levelFilter = 'DEBUG';
  let searchFilter = '';
  let searchInput = '';   // raw input, debounced → searchFilter
  let copiedIndex = -1;
  let maxLogs = $maxLogsStore;

  const levels = ['DEBUG', 'INFO', 'WARN', 'ERROR'];

  // ─── Debounce search input ────────────────────────────────────
  let debounceTimer = null;
  $: {
    clearTimeout(debounceTimer);
    const val = searchInput;
    debounceTimer = setTimeout(() => { searchFilter = val; }, 150);
  }

  // ─── Virtual scroll constants ─────────────────────────────────
  const ROW_HEIGHT = 24;  // fixed row height — no variable measurement
  const OVERSCAN = 15;
  let containerHeight = 0;
  let scrollTop = 0;
  let resizeObserver;

  // When maxLogs changes, persist and trim
  $: {
    maxLogsStore.set(maxLogs);
    logStore.trimToMax(maxLogs);
  }

  // ─── Filtering ────────────────────────────────────────────────
  // Direct field checks instead of formatEntry() + toLowerCase()
  $: filteredLogs = filterLogs($logStore, levelFilter, searchFilter);

  function filterLogs(logs, lvl, query) {
    const filterIdx = levels.indexOf(lvl);
    const q = query ? query.toLowerCase() : '';
    if (!q && filterIdx === 0) return logs; // no filter — pass through

    return logs.filter(entry => {
      const levelIdx = levels.indexOf(entry.level);
      if (levelIdx < filterIdx) return false;
      if (q) {
        // Check fields directly — avoid expensive Date formatting
        if (entry.message && entry.message.toLowerCase().includes(q)) return true;
        if (entry.tag && entry.tag.toLowerCase().includes(q)) return true;
        if (entry.level && entry.level.toLowerCase().includes(q)) return true;
        return false;
      }
      return true;
    });
  }

  // ─── Virtual scroll calculations ──────────────────────────────
  // Fixed row height — O(1) position calculation, no measurement needed
  $: totalHeight = filteredLogs.length * ROW_HEIGHT;

  $: visibleRange = computeVisibleRange(scrollTop, containerHeight, filteredLogs.length);

  function computeVisibleRange(st, ch, totalCount) {
    if (totalCount === 0 || ch === 0) return { start: 0, end: 0 };

    const startIdx = Math.floor(st / ROW_HEIGHT);
    const endIdx = Math.ceil((st + ch) / ROW_HEIGHT);

    const start = Math.max(0, startIdx - OVERSCAN);
    const end = Math.min(totalCount, endIdx + OVERSCAN);
    return { start, end };
  }

  $: visibleItems = filteredLogs.slice(visibleRange.start, visibleRange.end).map((entry, i) => ({
    entry,
    index: visibleRange.start + i,
  }));

  // ─── Scroll & auto-scroll ─────────────────────────────────────
  let scrollRafId = null;

  function handleScroll() {
    if (scrollRafId !== null) return; // throttle to 1 per frame
    scrollRafId = requestAnimationFrame(() => {
      scrollRafId = null;
      if (!logsContainer) return;
      scrollTop = logsContainer.scrollTop;
      const { scrollHeight, clientHeight } = logsContainer;
      autoScroll = scrollHeight - scrollTop - clientHeight < 50;
    });
  }

  // Auto-scroll when new logs arrive
  let prevLogCount = 0;
  $: if (filteredLogs.length !== prevLogCount) {
    prevLogCount = filteredLogs.length;
    if (autoScroll && logsContainer) {
      tick().then(() => {
        if (logsContainer) {
          logsContainer.scrollTop = logsContainer.scrollHeight;
        }
      });
    }
  }

  function scrollToBottom() {
    autoScroll = true;
    if (logsContainer) {
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
  }

  // ─── Resize observer ──────────────────────────────────────────
  onMount(() => {
    if (logsContainer) {
      containerHeight = logsContainer.clientHeight;
      resizeObserver = new ResizeObserver(entries => {
        for (const entry of entries) {
          containerHeight = entry.contentRect.height;
        }
      });
      resizeObserver.observe(logsContainer);
    }
  });

  onDestroy(() => {
    if (resizeObserver) resizeObserver.disconnect();
    clearTimeout(debounceTimer);
    if (scrollRafId !== null) cancelAnimationFrame(scrollRafId);
  });

  // ─── Formatting & actions ─────────────────────────────────────
  function formatTs(ts) {
    if (!ts) return '';
    return new Date(ts).toLocaleTimeString('ru-RU');
  }

  function formatEntry(entry) {
    const ts = formatTs(entry.timestamp);
    const tag = entry.tag ? ` [${entry.tag}]` : '';
    return `${ts} [${entry.level || ''}]${tag} ${entry.message || ''}`;
  }

  async function copyEntry(entry, index) {
    await Clipboard.SetText(formatEntry(entry));
    copiedIndex = index;
    setTimeout(() => { copiedIndex = -1; }, 1500);
  }

  async function saveLogs() {
    const path = await Dialogs.SaveFile({
      Title: $t('logs.saveLogsDialog'),
      Filename: `awg-logs-${new Date().toISOString().slice(0, 10)}.log`,
      Filters: [{ DisplayName: 'Log files', Pattern: '*.log;*.txt' }],
    });
    if (!path) return;

    const content = filteredLogs.map(formatEntry).join('\n');
    await Call.ByName("main.BindingService.SaveLogsToFile", path, content);
  }

  function clearLogs() {
    logStore.clear();
  }

  function levelColor(level) {
    switch (level) {
      case 'ERROR': return 'text-red-400';
      case 'WARN': return 'text-yellow-400';
      case 'INFO': return 'text-blue-400';
      case 'DEBUG': return 'text-zinc-500';
      default: return 'text-zinc-400';
    }
  }

  function tagColor(tag) {
    const colors = [
      'text-cyan-400', 'text-violet-400', 'text-emerald-400',
      'text-orange-400', 'text-pink-400', 'text-teal-400',
    ];
    let hash = 0;
    for (let i = 0; i < tag.length; i++) {
      hash = tag.charCodeAt(i) + ((hash << 5) - hash);
    }
    return colors[Math.abs(hash) % colors.length];
  }
</script>

<div class="flex flex-col h-full">
  <!-- Toolbar -->
  <div class="flex items-center gap-3 p-3 border-b border-zinc-700/40 shrink-0 flex-wrap">
    <select
      bind:value={levelFilter}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 focus:outline-none"
    >
      {#each levels as level}
        <option value={level}>{level}+</option>
      {/each}
    </select>

    <input
      type="text"
      bind:value={searchInput}
      placeholder={$t('logs.filterPlaceholder')}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 placeholder-zinc-600 focus:outline-none w-48"
    />

    <select
      bind:value={maxLogs}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 focus:outline-none"
      title={$t('logs.maxEntriesTitle')}
    >
      {#each ALLOWED_LIMITS as limit}
        <option value={limit}>{limit} {$t('logs.entries')}</option>
      {/each}
    </select>

    <div class="flex-1"></div>

    <span class="text-xs text-zinc-500">{filteredLogs.length} {$t('logs.entries')}</span>

    {#if !autoScroll}
      <button
        class="px-2 py-1 text-xs bg-blue-600/20 text-blue-400 rounded hover:bg-blue-600/30 transition-colors"
        on:click={scrollToBottom}
      >
        {$t('logs.scrollDown')}
      </button>
    {/if}

    <button
      class="px-2 py-1 text-xs bg-zinc-700/50 text-zinc-400 rounded hover:bg-zinc-700 transition-colors"
      on:click={saveLogs}
      title={$t('logs.saveLogsTitle')}
    >
      {$t('logs.saveLogs')}
    </button>

    <button
      class="px-2 py-1 text-xs bg-zinc-700/50 text-zinc-400 rounded hover:bg-zinc-700 transition-colors"
      on:click={clearLogs}
    >
      {$t('logs.clear')}
    </button>
  </div>

  <!-- Log entries with virtual scroll (fixed row height) -->
  <div
    bind:this={logsContainer}
    on:scroll={handleScroll}
    class="flex-1 overflow-y-auto font-mono text-xs"
    style="contain: strict;"
  >
    {#if filteredLogs.length === 0}
      <div class="flex items-center justify-center h-full text-zinc-600">
        {$t('logs.noEntries')}
      </div>
    {:else}
      <div style="height: {totalHeight}px; position: relative; contain: layout style;">
        {#each visibleItems as { entry, index } (index)}
          <div
            class="flex gap-2 px-2 hover:bg-zinc-800/30 cursor-pointer transition-colors absolute w-full items-center"
            style="top: {index * ROW_HEIGHT}px; height: {ROW_HEIGHT}px;"
            class:log-copied={copiedIndex === index}
            role="button"
            tabindex="0"
            on:click={() => copyEntry(entry, index)}
            on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') copyEntry(entry, index); }}
            title={$t('logs.clickToCopy')}
          >
            <span class="text-zinc-600 shrink-0 w-18 tabular-nums truncate">
              {formatTs(entry.timestamp)}
            </span>
            <span class="shrink-0 w-11 {levelColor(entry.level)} font-semibold">
              {entry.level || ''}
            </span>
            {#if entry.tag}
              <span class="shrink-0 {tagColor(entry.tag)}">
                [{entry.tag}]
              </span>
            {/if}
            <span class="text-zinc-300 truncate flex-1">{entry.message || ''}</span>
            {#if copiedIndex === index}
              <span class="shrink-0 text-green-400 ml-auto pr-1">{$t('logs.copied')}</span>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .log-copied {
    background-color: rgba(20, 83, 45, 0.2);
  }
</style>

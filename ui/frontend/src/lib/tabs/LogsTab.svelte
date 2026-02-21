<script>
  import { onMount, onDestroy, afterUpdate, tick } from 'svelte';
  import { Events } from '@wailsio/runtime';

  let logs = [];
  let autoScroll = true;
  let logsContainer;
  let levelFilter = 'DEBUG';
  let tagFilter = '';

  const levels = ['DEBUG', 'INFO', 'WARN', 'ERROR'];

  // Subscribe to log stream events from backend
  let unsubscribe;

  onMount(() => {
    unsubscribe = Events.On('log-entry', (event) => {
      const entry = event.data;
      if (!entry) return;
      logs = [...logs, entry];
      // Cap at 5000 entries
      if (logs.length > 5000) {
        logs = logs.slice(logs.length - 5000);
      }
    });
  });

  onDestroy(() => {
    if (unsubscribe) unsubscribe();
  });

  afterUpdate(() => {
    if (autoScroll && logsContainer) {
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
  });

  function handleScroll() {
    if (!logsContainer) return;
    const { scrollTop, scrollHeight, clientHeight } = logsContainer;
    // Auto-scroll if within 50px of bottom
    autoScroll = scrollHeight - scrollTop - clientHeight < 50;
  }

  function clearLogs() {
    logs = [];
  }

  function scrollToBottom() {
    autoScroll = true;
    if (logsContainer) {
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
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
    // Stable color based on tag string hash
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

  $: filteredLogs = logs.filter(entry => {
    const levelIdx = levels.indexOf(entry.level);
    const filterIdx = levels.indexOf(levelFilter);
    if (levelIdx < filterIdx) return false;
    if (tagFilter && entry.tag && !entry.tag.toLowerCase().includes(tagFilter.toLowerCase())) return false;
    return true;
  });
</script>

<div class="flex flex-col h-full">
  <!-- Toolbar -->
  <div class="flex items-center gap-3 p-3 border-b border-zinc-700/40 shrink-0">
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
      bind:value={tagFilter}
      placeholder="Фильтр по тегу..."
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 placeholder-zinc-600 focus:outline-none w-36"
    />

    <div class="flex-1"></div>

    <span class="text-xs text-zinc-500">{filteredLogs.length} записей</span>

    {#if !autoScroll}
      <button
        class="px-2 py-1 text-xs bg-blue-600/20 text-blue-400 rounded hover:bg-blue-600/30 transition-colors"
        on:click={scrollToBottom}
      >
        Прокрутить вниз
      </button>
    {/if}

    <button
      class="px-2 py-1 text-xs bg-zinc-700/50 text-zinc-400 rounded hover:bg-zinc-700 transition-colors"
      on:click={clearLogs}
    >
      Очистить
    </button>
  </div>

  <!-- Log entries -->
  <div
    bind:this={logsContainer}
    on:scroll={handleScroll}
    class="flex-1 overflow-y-auto font-mono text-xs leading-relaxed p-2"
  >
    {#if filteredLogs.length === 0}
      <div class="flex items-center justify-center h-full text-zinc-600">
        Нет записей логов
      </div>
    {:else}
      {#each filteredLogs as entry}
        <div class="flex gap-2 py-0.5 hover:bg-zinc-800/30">
          <span class="text-zinc-600 shrink-0 w-18 tabular-nums">
            {entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString('ru-RU') : ''}
          </span>
          <span class="shrink-0 w-11 {levelColor(entry.level)} font-semibold">
            {entry.level || ''}
          </span>
          {#if entry.tag}
            <span class="shrink-0 {tagColor(entry.tag)}">
              [{entry.tag}]
            </span>
          {/if}
          <span class="text-zinc-300 break-all">{entry.message || ''}</span>
        </div>
      {/each}
    {/if}
  </div>
</div>

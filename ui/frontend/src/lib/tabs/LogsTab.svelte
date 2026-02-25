<script>
  import { afterUpdate } from 'svelte';
  import { Clipboard, Dialogs, Call } from '@wailsio/runtime';
  import { logStore } from '../stores/logs.js';
  import { t } from '../i18n';

  let autoScroll = true;
  let logsContainer;
  let levelFilter = 'DEBUG';
  let tagFilter = '';
  let copiedIndex = -1;

  const levels = ['DEBUG', 'INFO', 'WARN', 'ERROR'];

  afterUpdate(() => {
    if (autoScroll && logsContainer) {
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
  });

  function handleScroll() {
    if (!logsContainer) return;
    const { scrollTop, scrollHeight, clientHeight } = logsContainer;
    autoScroll = scrollHeight - scrollTop - clientHeight < 50;
  }

  function clearLogs() {
    logStore.clear();
  }

  function scrollToBottom() {
    autoScroll = true;
    if (logsContainer) {
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
  }

  function formatEntry(entry) {
    const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleTimeString('ru-RU') : '';
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

  $: filteredLogs = $logStore.filter(entry => {
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
      placeholder={$t('logs.filterTag')}
      class="px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-300 placeholder-zinc-600 focus:outline-none w-36"
    />

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

  <!-- Log entries -->
  <div
    bind:this={logsContainer}
    on:scroll={handleScroll}
    class="flex-1 overflow-y-auto font-mono text-xs leading-relaxed p-2"
  >
    {#if filteredLogs.length === 0}
      <div class="flex items-center justify-center h-full text-zinc-600">
        {$t('logs.noEntries')}
      </div>
    {:else}
      {#each filteredLogs as entry, i}
        <div
          class="flex gap-2 py-0.5 hover:bg-zinc-800/30 cursor-pointer rounded transition-colors"
          class:bg-green-900={copiedIndex === i}
          style="background-color: {copiedIndex === i ? 'rgba(20, 83, 45, 0.2)' : 'transparent'}"
          role="button"
          tabindex="0"
          on:click={() => copyEntry(entry, i)}
          on:keydown={(e) => { if (e.key === 'Enter' || e.key === ' ') copyEntry(entry, i); }}
          title={$t('logs.clickToCopy')}
        >
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
          {#if copiedIndex === i}
            <span class="shrink-0 text-green-400 ml-auto pr-1">{$t('logs.copied')}</span>
          {/if}
        </div>
      {/each}
    {/if}
  </div>
</div>

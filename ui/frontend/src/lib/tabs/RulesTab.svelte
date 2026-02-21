<script>
  import { onMount } from 'svelte';
  import * as api from '../api.js';

  let rules = [];
  let tunnels = [];
  let loading = true;
  let error = '';
  let dirty = false;

  // Modal state
  let showModal = false;
  let editIndex = -1;
  let modalRule = { pattern: '', tunnelId: '', fallback: 'allow_direct', priority: 'auto' };

  // Drag & drop reorder
  let dragIndex = -1;
  let dragOverIndex = -1;

  function handleDragStart(e, index) {
    dragIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(index));
    // Semi-transparent drag image
    e.currentTarget.closest('tr').style.opacity = '0.4';
  }

  function handleDragEnd(e) {
    e.currentTarget.closest('tr').style.opacity = '';
    dragIndex = -1;
    dragOverIndex = -1;
  }

  function handleDragOver(e, index) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    dragOverIndex = index;
  }

  function handleDragLeave() {
    dragOverIndex = -1;
  }

  function handleDrop(e, index) {
    e.preventDefault();
    if (dragIndex < 0 || dragIndex === index) {
      dragIndex = -1;
      dragOverIndex = -1;
      return;
    }
    const reordered = [...rules];
    const [moved] = reordered.splice(dragIndex, 1);
    reordered.splice(index, 0, moved);
    rules = reordered;
    dirty = true;
    dragIndex = -1;
    dragOverIndex = -1;
  }

  // Process picker
  let showProcessPicker = false;
  let processes = [];
  let processFilter = '';
  let processLoading = false;

  onMount(async () => {
    await loadData();
  });

  async function loadData() {
    loading = true;
    error = '';
    try {
      const [r, t] = await Promise.all([api.listRules(), api.listTunnels()]);
      rules = r || [];
      tunnels = t || [];
    } catch (e) {
      error = e.message || 'Не удалось загрузить данные';
    } finally {
      loading = false;
    }
  }

  function openAddModal() {
    editIndex = -1;
    modalRule = { pattern: '', tunnelId: '', fallback: 'allow_direct', priority: 'auto' };
    showModal = true;
  }

  function openEditModal(index) {
    editIndex = index;
    modalRule = { ...rules[index] };
    showModal = true;
  }

  function closeModal() {
    showModal = false;
    showProcessPicker = false;
  }

  function saveModalRule() {
    if (!modalRule.pattern.trim()) return;
    if (editIndex >= 0) {
      rules[editIndex] = { ...modalRule };
    } else {
      rules = [...rules, { ...modalRule }];
    }
    dirty = true;
    closeModal();
  }

  function removeRule(index) {
    rules = rules.filter((_, i) => i !== index);
    dirty = true;
  }

  async function save() {
    error = '';
    try {
      await api.saveRules(rules);
      dirty = false;
    } catch (e) {
      error = e.message;
    }
  }

  function cancel() {
    loadData();
    dirty = false;
  }

  async function openProcessPicker() {
    showProcessPicker = true;
    processLoading = true;
    processFilter = '';
    try {
      processes = await api.listProcesses('') || [];
    } catch (e) {
      processes = [];
    } finally {
      processLoading = false;
    }
  }

  async function filterProcesses() {
    processLoading = true;
    try {
      processes = await api.listProcesses(processFilter) || [];
    } catch (e) {
      processes = [];
    } finally {
      processLoading = false;
    }
  }

  function selectProcess(proc) {
    modalRule.pattern = proc.name;
    showProcessPicker = false;
  }

  function tunnelName(id) {
    if (!id) return 'Не назначен';
    const t = tunnels.find(t => t.id === id);
    return t ? (t.name || t.id) : id;
  }

  function fallbackLabel(fb) {
    switch (fb) {
      case 'block': return 'Блокировать';
      case 'drop': return 'Отбросить';
      case 'failover': return 'Следующее правило';
      default: return 'Прямой доступ';
    }
  }

  function priorityLabel(p) {
    switch (p) {
      case 'realtime': return 'Realtime';
      case 'normal': return 'Normal';
      case 'low': return 'Low';
      default: return 'Auto';
    }
  }

  function priorityColor(p) {
    switch (p) {
      case 'realtime': return 'text-orange-400 bg-orange-400/10';
      case 'normal': return 'text-blue-400 bg-blue-400/10';
      case 'low': return 'text-zinc-400 bg-zinc-400/10';
      default: return 'text-green-400 bg-green-400/10';
    }
  }
</script>

<div class="p-4 space-y-4">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">Правила маршрутизации</h2>
    <div class="flex items-center gap-2">
      {#if dirty}
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
          on:click={cancel}
        >
          Отмена
        </button>
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
          on:click={save}
        >
          Сохранить
        </button>
      {/if}
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
        on:click={openAddModal}
      >
        + Добавить правило
      </button>
    </div>
  </div>

  {#if error}
    <div class="px-3 py-2 text-sm bg-red-900/30 border border-red-800/50 rounded-lg text-red-300">
      {error}
    </div>
  {/if}

  {#if loading}
    <div class="flex items-center justify-center py-12 text-zinc-500">
      <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24" fill="none">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
      </svg>
      Загрузка...
    </div>
  {:else if rules.length === 0}
    <div class="flex flex-col items-center justify-center py-16 text-zinc-500">
      <svg class="w-12 h-12 mb-3 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
        <path d="M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z"/>
      </svg>
      <p class="text-sm">Нет правил маршрутизации</p>
      <p class="text-xs text-zinc-600 mt-1">Весь трафик будет направлен напрямую</p>
    </div>
  {:else}
    <!-- Rules table -->
    <div class="border border-zinc-700/40 rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-zinc-800/60 text-zinc-400 text-xs uppercase tracking-wider">
            <th class="w-8 px-0 py-2.5"></th>
            <th class="text-left px-4 py-2.5 font-medium">Паттерн</th>
            <th class="text-left px-4 py-2.5 font-medium">Туннель</th>
            <th class="text-left px-4 py-2.5 font-medium">Fallback</th>
            <th class="text-left px-4 py-2.5 font-medium">Приоритет</th>
            <th class="text-right px-4 py-2.5 font-medium w-24"></th>
          </tr>
        </thead>
        <tbody>
          {#each rules as rule, index (rule.pattern + '-' + index)}
            <tr
              class="border-t border-zinc-700/30 hover:bg-zinc-800/30 transition-colors {rule.active === false ? 'opacity-50' : ''} {dragOverIndex === index ? 'border-t-2 !border-t-blue-500' : ''}"
              on:dragover={e => handleDragOver(e, index)}
              on:dragleave={handleDragLeave}
              on:drop={e => handleDrop(e, index)}
            >
              <!-- Drag handle -->
              <td class="w-8 px-0 py-2.5 text-center">
                <!-- svelte-ignore a11y-no-static-element-interactions -->
                <div
                  class="inline-flex items-center justify-center w-6 h-6 cursor-grab active:cursor-grabbing text-zinc-600 hover:text-zinc-400 transition-colors"
                  draggable="true"
                  on:dragstart={e => handleDragStart(e, index)}
                  on:dragend={handleDragEnd}
                >
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                    <circle cx="9" cy="6" r="1.5"/><circle cx="15" cy="6" r="1.5"/>
                    <circle cx="9" cy="12" r="1.5"/><circle cx="15" cy="12" r="1.5"/>
                    <circle cx="9" cy="18" r="1.5"/><circle cx="15" cy="18" r="1.5"/>
                  </svg>
                </div>
              </td>
              <td class="px-4 py-2.5 font-mono text-xs {rule.active === false ? 'text-zinc-500' : 'text-zinc-200'}">
                {rule.pattern}
                {#if rule.active === false}
                  <span class="ml-1.5 inline-block px-1.5 py-0.5 text-[10px] rounded bg-zinc-700/50 text-zinc-500 font-sans">offline</span>
                {/if}
              </td>
              <td class="px-4 py-2.5 {rule.active === false ? 'text-zinc-500' : 'text-zinc-300'}">{tunnelName(rule.tunnelId)}</td>
              <td class="px-4 py-2.5 {rule.active === false ? 'text-zinc-500' : 'text-zinc-400'}">{fallbackLabel(rule.fallback)}</td>
              <td class="px-4 py-2.5">
                <span class="inline-block px-1.5 py-0.5 text-xs rounded {priorityColor(rule.priority)}">
                  {priorityLabel(rule.priority)}
                </span>
              </td>
              <td class="px-4 py-2.5 text-right">
                <button
                  class="text-zinc-500 hover:text-zinc-200 transition-colors mr-2"
                  on:click={() => openEditModal(index)}
                >
                  <svg class="w-3.5 h-3.5 inline" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1.003 1.003 0 000-1.42l-2.34-2.34a1.003 1.003 0 00-1.42 0l-1.83 1.83 3.75 3.75 1.84-1.82z"/>
                  </svg>
                </button>
                <button
                  class="text-zinc-500 hover:text-red-400 transition-colors"
                  on:click={() => removeRule(index)}
                >
                  <svg class="w-3.5 h-3.5 inline" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                  </svg>
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<!-- Rule modal -->
{#if showModal}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="fixed inset-0 bg-black/60 z-40 flex items-center justify-center"
       on:click|self={closeModal}
       on:keydown={e => e.key === 'Escape' && closeModal()}
       role="dialog"
       tabindex="-1"
  >
    <div class="bg-zinc-800 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-md mx-4 p-5 space-y-4">
      <h3 class="text-base font-semibold text-zinc-100">
        {editIndex >= 0 ? 'Редактировать правило' : 'Новое правило'}
      </h3>

      <div class="space-y-3">
        <!-- Pattern -->
        <div>
          <label for="rule-pattern" class="block text-xs font-medium text-zinc-400 mb-1">Паттерн процесса</label>
          <div class="flex gap-2">
            <input
              id="rule-pattern"
              type="text"
              bind:value={modalRule.pattern}
              placeholder="chrome.exe, firefox*, C:\Program Files\..."
              class="flex-1 px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
            />
            <button
              class="px-2.5 py-2 text-xs bg-zinc-700 text-zinc-300 rounded-lg hover:bg-zinc-600 transition-colors shrink-0"
              title="Выбрать процесс"
              on:click={openProcessPicker}
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M15.5 14h-.79l-.28-.27A6.471 6.471 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
              </svg>
            </button>
          </div>
        </div>

        <!-- Process picker inline -->
        {#if showProcessPicker}
          <div class="bg-zinc-900 border border-zinc-700 rounded-lg p-2 max-h-40 overflow-y-auto">
            <input
              type="text"
              bind:value={processFilter}
              on:input={filterProcesses}
              placeholder="Фильтр..."
              class="w-full px-2 py-1 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-200 placeholder-zinc-600 focus:outline-none mb-1"
            />
            {#if processLoading}
              <div class="text-xs text-zinc-500 py-2 text-center">Загрузка...</div>
            {:else}
              {#each processes.slice(0, 50) as proc}
                <button
                  class="w-full text-left px-2 py-1 text-xs text-zinc-300 hover:bg-zinc-800 rounded truncate"
                  on:click={() => selectProcess(proc)}
                >
                  <span class="text-zinc-200">{proc.name}</span>
                  <span class="text-zinc-600 ml-1">PID {proc.pid}</span>
                </button>
              {/each}
            {/if}
          </div>
        {/if}

        <!-- Tunnel -->
        <div>
          <label for="rule-tunnel" class="block text-xs font-medium text-zinc-400 mb-1">Туннель</label>
          <select
            id="rule-tunnel"
            bind:value={modalRule.tunnelId}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="">Не назначен</option>
            {#each tunnels as t}
              <option value={t.id}>{t.name || t.id} ({t.protocol})</option>
            {/each}
            <option value="__block__">Блокировать</option>
            <option value="__drop__">Отбросить (drop)</option>
          </select>
        </div>

        <!-- Fallback -->
        <div>
          <label for="rule-fallback" class="block text-xs font-medium text-zinc-400 mb-1">Fallback (если туннель недоступен)</label>
          <select
            id="rule-fallback"
            bind:value={modalRule.fallback}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="allow_direct">Прямой доступ</option>
            <option value="block">Блокировать</option>
            <option value="drop">Отбросить</option>
            <option value="failover">Следующее правило</option>
          </select>
        </div>

        <!-- Priority -->
        <div>
          <label for="rule-priority" class="block text-xs font-medium text-zinc-400 mb-1">Приоритет QoS</label>
          <select
            id="rule-priority"
            bind:value={modalRule.priority}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="auto">Auto (по характеристикам пакета)</option>
            <option value="realtime">Realtime (высокий приоритет)</option>
            <option value="normal">Normal (обычный приоритет)</option>
            <option value="low">Low (низкий приоритет)</option>
          </select>
        </div>
      </div>

      <div class="flex justify-end gap-2 pt-2">
        <button
          class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
          on:click={closeModal}
        >
          Отмена
        </button>
        <button
          class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
          disabled={!modalRule.pattern.trim()}
          on:click={saveModalRule}
        >
          {editIndex >= 0 ? 'Сохранить' : 'Добавить'}
        </button>
      </div>
    </div>
  </div>
{/if}

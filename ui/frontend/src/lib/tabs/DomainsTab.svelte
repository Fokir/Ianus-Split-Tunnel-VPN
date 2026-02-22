<script>
  import { onMount } from 'svelte';
  import * as api from '../api.js';

  let rules = [];
  let tunnels = [];
  let loading = true;
  let error = '';
  let dirty = false;

  // Geosite
  let geositeCategories = [];
  let geositeUpdating = false;

  // Modal state
  let showModal = false;
  let editIndex = -1;
  let modalRule = { patternType: 'domain', patternValue: '', tunnelId: '', action: 'route' };

  // Geosite category search
  let categorySearch = '';
  let categoryDropdownOpen = false;
  let categoryHighlightIndex = -1;

  $: filteredCategories = geositeCategories.filter(
    cat => cat.toLowerCase().includes(categorySearch.toLowerCase())
  );

  // Drag & drop reorder
  let dragIndex = -1;
  let dragOverIndex = -1;

  function handleDragStart(e, index) {
    dragIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(index));
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

  onMount(async () => {
    await loadData();
  });

  async function loadData() {
    loading = true;
    error = '';
    try {
      const [r, t, cats] = await Promise.all([
        api.listDomainRules(),
        api.listTunnels(),
        api.listGeositeCategories().catch(() => [])
      ]);
      rules = r || [];
      tunnels = t || [];
      geositeCategories = cats || [];
    } catch (e) {
      error = e.message || 'Не удалось загрузить данные';
    } finally {
      loading = false;
    }
  }

  function parsePattern(pattern) {
    const idx = pattern.indexOf(':');
    if (idx > 0) {
      const prefix = pattern.substring(0, idx);
      if (['domain', 'full', 'keyword', 'geosite'].includes(prefix)) {
        return { type: prefix, value: pattern.substring(idx + 1) };
      }
    }
    return { type: 'domain', value: pattern };
  }

  function buildPattern(type, value) {
    return type + ':' + value;
  }

  function openAddModal() {
    editIndex = -1;
    modalRule = { patternType: 'domain', patternValue: '', tunnelId: '', action: 'route' };
    categorySearch = '';
    categoryDropdownOpen = false;
    categoryHighlightIndex = -1;
    showModal = true;
  }

  function openEditModal(index) {
    editIndex = index;
    const parsed = parsePattern(rules[index].pattern);
    modalRule = {
      patternType: parsed.type,
      patternValue: parsed.value,
      tunnelId: rules[index].tunnelId || '',
      action: rules[index].action || 'route'
    };
    categorySearch = parsed.type === 'geosite' ? parsed.value : '';
    categoryDropdownOpen = false;
    categoryHighlightIndex = -1;
    showModal = true;
  }

  function closeModal() {
    showModal = false;
    categoryDropdownOpen = false;
  }

  function saveModalRule() {
    if (!modalRule.patternValue.trim()) return;
    const pattern = buildPattern(modalRule.patternType, modalRule.patternValue.trim().toLowerCase());
    const rule = {
      pattern,
      tunnelId: modalRule.action === 'route' ? modalRule.tunnelId : '',
      action: modalRule.action,
      active: true
    };
    if (editIndex >= 0) {
      rules[editIndex] = rule;
      rules = rules;
    } else {
      rules = [...rules, rule];
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
      await api.saveDomainRules(rules);
      dirty = false;
    } catch (e) {
      error = e.message;
    }
  }

  function cancel() {
    loadData();
    dirty = false;
  }

  async function handleUpdateGeosite() {
    geositeUpdating = true;
    error = '';
    try {
      await api.updateGeosite();
      geositeCategories = await api.listGeositeCategories().catch(() => []);
    } catch (e) {
      error = e.message || 'Не удалось обновить geosite';
    } finally {
      geositeUpdating = false;
    }
  }

  function tunnelName(id) {
    if (!id) return '';
    const t = tunnels.find(t => t.id === id);
    return t ? (t.name || t.id) : id;
  }

  function actionLabel(action) {
    switch (action) {
      case 'direct': return 'Напрямую';
      case 'block': return 'Блокировать';
      default: return 'Туннель';
    }
  }

  function actionColor(action) {
    switch (action) {
      case 'direct': return 'text-green-400 bg-green-400/10';
      case 'block': return 'text-red-400 bg-red-400/10';
      default: return 'text-blue-400 bg-blue-400/10';
    }
  }

  function patternTypeLabel(type) {
    switch (type) {
      case 'full': return 'Точный';
      case 'keyword': return 'Ключевое слово';
      case 'geosite': return 'Geosite';
      default: return 'Домен';
    }
  }

  function patternTypeColor(type) {
    switch (type) {
      case 'full': return 'text-purple-400 bg-purple-400/10';
      case 'keyword': return 'text-yellow-400 bg-yellow-400/10';
      case 'geosite': return 'text-cyan-400 bg-cyan-400/10';
      default: return 'text-zinc-400 bg-zinc-400/10';
    }
  }

  // Category search handlers
  function handleCategoryInput(e) {
    categorySearch = e.target.value;
    categoryDropdownOpen = true;
    categoryHighlightIndex = -1;
    // Sync patternValue when user types manually
    modalRule.patternValue = categorySearch;
  }

  function handleCategoryFocus() {
    categoryDropdownOpen = true;
  }

  function handleCategoryBlur() {
    // Delay to allow click on dropdown item
    setTimeout(() => { categoryDropdownOpen = false; }, 150);
  }

  function selectCategory(cat) {
    categorySearch = cat;
    modalRule.patternValue = cat;
    categoryDropdownOpen = false;
    categoryHighlightIndex = -1;
  }

  function handleCategoryKeydown(e) {
    if (!categoryDropdownOpen || filteredCategories.length === 0) {
      if (e.key === 'ArrowDown') {
        categoryDropdownOpen = true;
        categoryHighlightIndex = 0;
        e.preventDefault();
      }
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      categoryHighlightIndex = Math.min(categoryHighlightIndex + 1, filteredCategories.length - 1);
      scrollHighlightedIntoView();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      categoryHighlightIndex = Math.max(categoryHighlightIndex - 1, 0);
      scrollHighlightedIntoView();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (categoryHighlightIndex >= 0 && categoryHighlightIndex < filteredCategories.length) {
        selectCategory(filteredCategories[categoryHighlightIndex]);
      }
    } else if (e.key === 'Escape') {
      categoryDropdownOpen = false;
    }
  }

  function scrollHighlightedIntoView() {
    requestAnimationFrame(() => {
      const el = document.querySelector('.category-dropdown-item.highlighted');
      if (el) el.scrollIntoView({ block: 'nearest' });
    });
  }
</script>

<div class="p-4 space-y-4">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">Маршрутизация по доменам</h2>
    <div class="flex items-center gap-2">
      <!-- Geosite update button -->
      <button
        class="px-2.5 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors flex items-center gap-1.5 disabled:opacity-40"
        on:click={handleUpdateGeosite}
        disabled={geositeUpdating}
        title="Обновить geosite.dat"
      >
        <svg class="w-3.5 h-3.5 {geositeUpdating ? 'animate-spin' : ''}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m0 0a9 9 0 019-9m-9 9a9 9 0 009 9" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        {geositeUpdating ? 'Обновление...' : 'Geosite'}
      </button>
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
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
      </svg>
      <p class="text-sm">Нет доменных правил</p>
      <p class="text-xs text-zinc-600 mt-1">Добавьте правила для маршрутизации трафика по доменам</p>
    </div>
  {:else}
    <div class="border border-zinc-700/40 rounded-lg overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-zinc-800/60 text-zinc-400 text-xs uppercase tracking-wider">
            <th class="w-8 px-0 py-2.5"></th>
            <th class="text-left px-4 py-2.5 font-medium">Паттерн</th>
            <th class="text-left px-4 py-2.5 font-medium">Тип</th>
            <th class="text-left px-4 py-2.5 font-medium">Действие</th>
            <th class="text-left px-4 py-2.5 font-medium">Туннель</th>
            <th class="text-right px-4 py-2.5 font-medium w-24"></th>
          </tr>
        </thead>
        <tbody>
          {#each rules as rule, index (rule.pattern + '-' + index)}
            {@const parsed = parsePattern(rule.pattern)}
            <tr
              class="border-t border-zinc-700/30 hover:bg-zinc-800/30 transition-colors {rule.active === false ? 'opacity-50' : ''} {dragOverIndex === index ? 'border-t-2 !border-t-blue-500' : ''}"
              on:dragover={e => handleDragOver(e, index)}
              on:dragleave={handleDragLeave}
              on:drop={e => handleDrop(e, index)}
            >
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
                {parsed.value}
                {#if rule.active === false}
                  <span class="ml-1.5 inline-block px-1.5 py-0.5 text-[10px] rounded bg-zinc-700/50 text-zinc-500 font-sans">не активен</span>
                {/if}
              </td>
              <td class="px-4 py-2.5">
                <span class="inline-block px-1.5 py-0.5 text-xs rounded {patternTypeColor(parsed.type)}">
                  {patternTypeLabel(parsed.type)}
                </span>
              </td>
              <td class="px-4 py-2.5">
                <span class="inline-block px-1.5 py-0.5 text-xs rounded {actionColor(rule.action)}">
                  {actionLabel(rule.action)}
                </span>
              </td>
              <td class="px-4 py-2.5 {rule.active === false ? 'text-zinc-500' : 'text-zinc-300'}">
                {rule.action === 'route' ? tunnelName(rule.tunnelId) : ''}
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

<!-- Domain rule modal -->
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
        {editIndex >= 0 ? 'Редактировать правило' : 'Новое доменное правило'}
      </h3>

      <div class="space-y-3">
        <!-- Pattern type -->
        <div>
          <label for="domain-type" class="block text-xs font-medium text-zinc-400 mb-1">Тип паттерна</label>
          <select
            id="domain-type"
            bind:value={modalRule.patternType}
            on:change={() => { modalRule.patternValue = ''; categorySearch = ''; categoryDropdownOpen = false; }}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="domain">domain: (домен и поддомены)</option>
            <option value="full">full: (точное совпадение)</option>
            <option value="keyword">keyword: (подстрока)</option>
            <option value="geosite">geosite: (категория V2Ray)</option>
          </select>
        </div>

        <!-- Pattern value -->
        <div>
          <label for="domain-value" class="block text-xs font-medium text-zinc-400 mb-1">
            {modalRule.patternType === 'geosite' ? 'Категория' : 'Значение'}
          </label>
          {#if modalRule.patternType === 'geosite' && geositeCategories.length > 0}
            <!-- Searchable category picker -->
            <div class="relative">
              <div class="relative">
                <input
                  id="domain-value"
                  type="text"
                  value={categorySearch}
                  on:input={handleCategoryInput}
                  on:focus={handleCategoryFocus}
                  on:blur={handleCategoryBlur}
                  on:keydown={handleCategoryKeydown}
                  placeholder="Поиск категории..."
                  autocomplete="off"
                  class="w-full px-3 py-2 pr-8 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
                />
                <svg class="absolute right-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-500 pointer-events-none" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>
                </svg>
              </div>
              {#if categoryDropdownOpen && filteredCategories.length > 0}
                <div class="absolute z-50 mt-1 w-full max-h-48 overflow-y-auto bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl">
                  {#each filteredCategories as cat, i}
                    <!-- svelte-ignore a11y-no-static-element-interactions -->
                    <div
                      class="category-dropdown-item px-3 py-1.5 text-sm cursor-pointer transition-colors
                             {i === categoryHighlightIndex ? 'highlighted bg-blue-600/30 text-blue-300' : 'text-zinc-300 hover:bg-zinc-800'}
                             {cat === modalRule.patternValue ? 'font-medium text-blue-400' : ''}"
                      on:mousedown|preventDefault={() => selectCategory(cat)}
                    >
                      {cat}
                    </div>
                  {/each}
                </div>
              {/if}
              {#if categoryDropdownOpen && categorySearch && filteredCategories.length === 0}
                <div class="absolute z-50 mt-1 w-full bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl">
                  <div class="px-3 py-2 text-sm text-zinc-500">Категория не найдена</div>
                </div>
              {/if}
            </div>
            {#if modalRule.patternValue && !categoryDropdownOpen}
              <div class="mt-1.5 text-xs text-zinc-500">
                Выбрано: <span class="text-cyan-400 font-medium">{modalRule.patternValue}</span>
              </div>
            {/if}
          {:else}
            <input
              id="domain-value"
              type="text"
              bind:value={modalRule.patternValue}
              placeholder={modalRule.patternType === 'geosite' ? 'ru, google, facebook' : 'vk.com, example.org'}
              class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
            />
          {/if}
        </div>

        <!-- Action -->
        <div>
          <label for="domain-action" class="block text-xs font-medium text-zinc-400 mb-1">Действие</label>
          <select
            id="domain-action"
            bind:value={modalRule.action}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="route">Через туннель</option>
            <option value="direct">Напрямую (мимо VPN)</option>
            <option value="block">Заблокировать</option>
          </select>
        </div>

        <!-- Tunnel (only for route action) -->
        {#if modalRule.action === 'route'}
          <div>
            <label for="domain-tunnel" class="block text-xs font-medium text-zinc-400 mb-1">Туннель</label>
            <select
              id="domain-tunnel"
              bind:value={modalRule.tunnelId}
              class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
            >
              <option value="">Выберите туннель...</option>
              {#each tunnels as t}
                <option value={t.id}>{t.name || t.id} ({t.protocol})</option>
              {/each}
            </select>
          </div>
        {/if}
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
          disabled={!modalRule.patternValue.trim() || (modalRule.action === 'route' && !modalRule.tunnelId)}
          on:click={saveModalRule}
        >
          {editIndex >= 0 ? 'Сохранить' : 'Добавить'}
        </button>
      </div>
    </div>
  </div>
{/if}

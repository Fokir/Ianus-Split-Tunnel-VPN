<script>
  import { onMount } from 'svelte';
  import * as api from '../api.js';
  import ErrorAlert from '../ErrorAlert.svelte';

  let config = null;
  let autostart = null;
  let loading = true;
  let error = '';
  let dirty = false;
  let saving = false;
  let tunnels = [];

  // DNS cache section expanded
  let dnsCacheExpanded = false;

  // Auto-update toggle (persisted in localStorage)
  let autoUpdateEnabled = localStorage.getItem('autoUpdateEnabled') !== 'false';

  onMount(async () => {
    await loadData();
  });

  async function loadData() {
    loading = true;
    error = '';
    try {
      const [cfg, as, tl] = await Promise.all([
        api.getConfig(),
        api.getAutostart(),
        api.listTunnels(),
      ]);
      config = cfg || {};
      autostart = as || { enabled: false, restoreConnections: false };
      tunnels = tl || [];

      // Ensure nested objects exist (field names must match proto JSON: snake_case)
      if (!config.dns) config.dns = {};
      if (!config.dns.servers || config.dns.servers.length === 0) {
        config.dns.servers = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9'];
      }
      if (!config.dns.cache) config.dns.cache = { enabled: true, max_size: 10000, max_ttl: '5m', min_ttl: '30s', neg_ttl: '60s' };
      if (!config.logging) config.logging = { level: 'INFO' };
    } catch (e) {
      error = e.message || 'Не удалось загрузить конфигурацию';
    } finally {
      loading = false;
    }
  }

  function markDirty() {
    dirty = true;
  }

  async function save() {
    saving = true;
    error = '';
    try {
      // Save config (with restart if connected)
      await api.saveConfig(config, true);

      // Save autostart separately (both enabled and restoreConnections)
      await api.setAutostart(autostart.enabled, autostart.restoreConnections);

      // Persist auto-update preference
      localStorage.setItem('autoUpdateEnabled', autoUpdateEnabled);

      dirty = false;
    } catch (e) {
      error = e.message;
    } finally {
      saving = false;
    }
  }

  async function cancel() {
    await loadData();
    dirty = false;
  }

  function addDnsServer() {
    config.dns.servers = [...config.dns.servers, ''];
    markDirty();
  }

  function removeDnsServer(index) {
    config.dns.servers = config.dns.servers.filter((_, i) => i !== index);
    markDirty();
  }

  function updateDnsServer(index, value) {
    config.dns.servers[index] = value;
    config.dns.servers = [...config.dns.servers];
    markDirty();
  }

  function handleIpv4Input(e, index) {
    const filtered = e.target.value.replace(/[^0-9.]/g, '');
    e.target.value = filtered;
    updateDnsServer(index, filtered);
  }

  function isValidIpv4(value) {
    if (!value) return true;
    const octets = value.split('.');
    if (octets.length !== 4) return false;
    for (const o of octets) {
      if (!o || o.length > 3) return false;
      const n = parseInt(o, 10);
      if (isNaN(n) || n < 0 || n > 255) return false;
      if (o.length > 1 && o[0] === '0') return false;
    }
    return true;
  }
</script>

<div class="p-4 space-y-6">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">Настройки</h2>
    {#if dirty}
      <div class="flex items-center gap-2">
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
          on:click={cancel}
          disabled={saving}
        >
          Отмена
        </button>
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
          on:click={save}
          disabled={saving}
        >
          {saving ? 'Сохранение...' : 'Сохранить'}
        </button>
      </div>
    {/if}
  </div>

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
  {:else if config}
    <!-- General -->
    <section class="space-y-3">
      <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">Основные</h3>
      <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4 space-y-3">
        <label class="flex items-center justify-between cursor-pointer">
          <div>
            <div class="text-sm text-zinc-200">Автозапуск</div>
            <div class="text-xs text-zinc-500">Запускать при входе в систему</div>
          </div>
          <input
            type="checkbox"
            bind:checked={autostart.enabled}
            on:change={markDirty}
            class="w-9 h-5 bg-zinc-700 rounded-full appearance-none relative cursor-pointer
                   checked:bg-blue-600 transition-colors
                   after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4
                   after:bg-white after:rounded-full after:transition-transform
                   checked:after:translate-x-4"
          />
        </label>
        <label class="flex items-center justify-between cursor-pointer">
          <div>
            <div class="text-sm text-zinc-200">Восстанавливать подключения</div>
            <div class="text-xs text-zinc-500">Автоподключение туннелей при старте</div>
          </div>
          <input
            type="checkbox"
            bind:checked={autostart.restoreConnections}
            on:change={markDirty}
            class="w-9 h-5 bg-zinc-700 rounded-full appearance-none relative cursor-pointer
                   checked:bg-blue-600 transition-colors
                   after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4
                   after:bg-white after:rounded-full after:transition-transform
                   checked:after:translate-x-4"
          />
        </label>
      </div>
    </section>

    <!-- Updates -->
    <section class="space-y-3">
      <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">Обновления</h3>
      <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4">
        <label class="flex items-center justify-between cursor-pointer">
          <div>
            <div class="text-sm text-zinc-200">Автопроверка обновлений</div>
            <div class="text-xs text-zinc-500">Периодически проверять новые версии</div>
          </div>
          <input
            type="checkbox"
            checked={autoUpdateEnabled}
            on:change={e => { autoUpdateEnabled = e.target.checked; markDirty(); }}
            class="w-9 h-5 bg-zinc-700 rounded-full appearance-none relative cursor-pointer
                   checked:bg-blue-600 transition-colors
                   after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4
                   after:bg-white after:rounded-full after:transition-transform
                   checked:after:translate-x-4"
          />
        </label>
      </div>
    </section>

    <!-- DNS -->
    <section class="space-y-3">
      <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">DNS</h3>
      <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4 space-y-3">
        <div>
          <label for="dns-tunnel" class="block text-xs font-medium text-zinc-400 mb-1">Туннель для DNS</label>
          <select
            id="dns-tunnel"
            bind:value={config.dns.tunnel_id}
            on:change={markDirty}
            class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
          >
            <option value="">По умолчанию</option>
            {#each tunnels as t}
              <option value={t.id}>{t.name || t.id}</option>
            {/each}
          </select>
        </div>

        <div>
          <!-- svelte-ignore a11y-label-has-associated-control -->
          <label class="block text-xs font-medium text-zinc-400 mb-2">DNS серверы</label>
          <div class="space-y-1.5">
            {#each config.dns.servers as server, i}
              <div class="flex gap-1.5">
                <input
                  type="text"
                  value={server}
                  on:input={e => handleIpv4Input(e, i)}
                  placeholder="0.0.0.0"
                  class="flex-1 px-3 py-1.5 text-sm bg-zinc-900 border rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none font-mono {server && !isValidIpv4(server) ? 'border-red-500/60 focus:border-red-500/80' : 'border-zinc-700 focus:border-blue-500/50'}"
                />
                <button
                  class="px-2 text-zinc-500 hover:text-red-400 transition-colors"
                  on:click={() => removeDnsServer(i)}
                >
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
                  </svg>
                </button>
              </div>
            {/each}
          </div>
          <button
            class="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
            on:click={addDnsServer}
          >
            + Добавить сервер
          </button>
        </div>
      </div>
    </section>

    <!-- DNS Cache -->
    <section class="space-y-3">
      <button
        class="flex items-center gap-2 text-sm font-medium text-zinc-400 uppercase tracking-wider hover:text-zinc-300 transition-colors"
        on:click={() => dnsCacheExpanded = !dnsCacheExpanded}
      >
        <svg class="w-3.5 h-3.5 transition-transform {dnsCacheExpanded ? 'rotate-90' : ''}" viewBox="0 0 24 24" fill="currentColor">
          <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/>
        </svg>
        DNS Кэш
      </button>
      {#if dnsCacheExpanded}
        <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4 space-y-3">
          <label class="flex items-center justify-between cursor-pointer">
            <div>
              <div class="text-sm text-zinc-200">Включен</div>
              <div class="text-xs text-zinc-500">Кэшировать DNS ответы для ускорения</div>
            </div>
            <input
              type="checkbox"
              bind:checked={config.dns.cache.enabled}
              on:change={markDirty}
              class="w-9 h-5 bg-zinc-700 rounded-full appearance-none relative cursor-pointer
                     checked:bg-blue-600 transition-colors
                     after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4
                     after:bg-white after:rounded-full after:transition-transform
                     checked:after:translate-x-4"
            />
          </label>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="dns-cache-ttl" class="block text-xs font-medium text-zinc-400 mb-1">Max TTL</label>
              <input
                id="dns-cache-ttl"
                type="text"
                bind:value={config.dns.cache.max_ttl}
                on:input={markDirty}
                placeholder="5m"
                class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>
            <div>
              <label for="dns-cache-entries" class="block text-xs font-medium text-zinc-400 mb-1">Max записей</label>
              <input
                id="dns-cache-entries"
                type="number"
                bind:value={config.dns.cache.max_size}
                on:input={markDirty}
                class="w-full px-3 py-1.5 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
              />
            </div>
          </div>
        </div>
      {/if}
    </section>

    <!-- Logging -->
    <section class="space-y-3">
      <h3 class="text-sm font-medium text-zinc-400 uppercase tracking-wider">Логирование</h3>
      <div class="bg-zinc-800/40 border border-zinc-700/40 rounded-lg p-4">
        <label for="log-level" class="block text-xs font-medium text-zinc-400 mb-1">Уровень логирования</label>
        <select
          id="log-level"
          bind:value={config.logging.level}
          on:change={markDirty}
          class="w-full px-3 py-2 text-sm bg-zinc-900 border border-zinc-700 rounded-lg text-zinc-200 focus:outline-none focus:border-blue-500/50"
        >
          <option value="DEBUG">DEBUG</option>
          <option value="INFO">INFO</option>
          <option value="WARN">WARN</option>
          <option value="ERROR">ERROR</option>
        </select>
      </div>
    </section>
  {/if}
</div>

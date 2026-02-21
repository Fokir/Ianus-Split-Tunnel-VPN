<script>
  import { onMount } from 'svelte';
  import * as api from '../api.js';

  let tunnels = [];
  let loading = true;
  let error = '';
  let showAddMenu = false;

  onMount(async () => {
    await refresh();
  });

  async function refresh() {
    loading = true;
    error = '';
    try {
      tunnels = (await api.listTunnels() || []).filter(t => t.id !== '__direct__');
    } catch (e) {
      error = e.message || 'Не удалось загрузить список туннелей';
    } finally {
      loading = false;
    }
  }

  async function connect(id) {
    try {
      await api.connectTunnel(id);
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function disconnect(id) {
    try {
      await api.disconnectTunnel(id);
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function restart(id) {
    try {
      await api.restartTunnel(id);
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function remove(id) {
    try {
      await api.removeTunnel(id);
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function connectAllTunnels() {
    try {
      await api.connectAll();
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function disconnectAllTunnels() {
    try {
      await api.disconnectAll();
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  let fileInput;

  function openAddMenu() {
    showAddMenu = !showAddMenu;
  }

  function handleAddAmneziaWG() {
    showAddMenu = false;
    fileInput.click();
  }

  async function handleFileSelected(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (ev) => {
      const data = new Uint8Array(ev.target.result);
      const name = file.name.replace(/\.conf$/i, '');
      try {
        await api.addTunnel({
          id: '',
          protocol: 'amneziawg',
          name: name,
          settings: {},
          configFileData: Array.from(data),
        });
        await refresh();
      } catch (err) {
        error = err.message;
      }
    };
    reader.readAsArrayBuffer(file);
    e.target.value = '';
  }

  function stateColor(state) {
    switch (state) {
      case 'up': return 'text-green-400';
      case 'connecting': return 'text-yellow-400';
      case 'error': return 'text-red-400';
      default: return 'text-zinc-500';
    }
  }

  function stateLabel(state) {
    switch (state) {
      case 'up': return 'Подключен';
      case 'connecting': return 'Подключение...';
      case 'error': return 'Ошибка';
      case 'down': return 'Отключен';
      default: return state;
    }
  }

  function stateDot(state) {
    switch (state) {
      case 'up': return 'bg-green-400';
      case 'connecting': return 'bg-yellow-400 animate-pulse';
      case 'error': return 'bg-red-400';
      default: return 'bg-zinc-500';
    }
  }
</script>

<div class="p-4 space-y-4">
  <!-- Header -->
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-zinc-100">Подключения</h2>
    <div class="flex items-center gap-2">
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-green-600/20 text-green-400 hover:bg-green-600/30 transition-colors"
        on:click={connectAllTunnels}
      >
        Подключить все
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={disconnectAllTunnels}
      >
        Отключить все
      </button>
      <div class="relative">
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
          on:click={openAddMenu}
        >
          + Добавить
        </button>
        {#if showAddMenu}
          <div class="absolute right-0 top-full mt-1 w-48 bg-zinc-800 border border-zinc-700 rounded-lg shadow-xl z-10">
            <button
              class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 rounded-lg transition-colors"
              on:click={handleAddAmneziaWG}
            >
              AmneziaWG (.conf)
            </button>
          </div>
        {/if}
      </div>
    </div>
  </div>

  <input
    bind:this={fileInput}
    type="file"
    accept=".conf"
    class="hidden"
    on:change={handleFileSelected}
  />

  <!-- Error -->
  {#if error}
    <div class="px-3 py-2 text-sm bg-red-900/30 border border-red-800/50 rounded-lg text-red-300">
      {error}
    </div>
  {/if}

  <!-- Loading -->
  {#if loading}
    <div class="flex items-center justify-center py-12 text-zinc-500">
      <svg class="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24" fill="none">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
      </svg>
      Загрузка...
    </div>
  {:else if tunnels.length === 0}
    <div class="flex flex-col items-center justify-center py-16 text-zinc-500">
      <svg class="w-12 h-12 mb-3 text-zinc-600" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
      </svg>
      <p class="text-sm">Нет настроенных туннелей</p>
      <p class="text-xs text-zinc-600 mt-1">Нажмите «+ Добавить» для создания нового подключения</p>
    </div>
  {:else}
    <!-- Tunnel list -->
    <div class="space-y-2">
      {#each tunnels as tunnel}
        <div class="flex items-center justify-between p-3 bg-zinc-800/50 border border-zinc-700/40 rounded-lg hover:bg-zinc-800/70 transition-colors">
          <div class="flex items-center gap-3 min-w-0">
            <span class="w-2 h-2 rounded-full shrink-0 {stateDot(tunnel.state)}"></span>
            <div class="min-w-0">
              <div class="text-sm font-medium text-zinc-200 truncate">
                {tunnel.name || tunnel.id}
              </div>
              <div class="flex items-center gap-2 text-xs text-zinc-500">
                <span class="uppercase">{tunnel.protocol}</span>
                {#if tunnel.adapterIp}
                  <span>&middot;</span>
                  <span>{tunnel.adapterIp}</span>
                {/if}
                <span>&middot;</span>
                <span class={stateColor(tunnel.state)}>{stateLabel(tunnel.state)}</span>
                {#if tunnel.error}
                  <span class="text-red-400 truncate">&mdash; {tunnel.error}</span>
                {/if}
              </div>
            </div>
          </div>

          <div class="flex items-center gap-1 shrink-0">
            {#if tunnel.state === 'up'}
              <button
                class="p-1.5 rounded-md text-zinc-400 hover:text-yellow-400 hover:bg-zinc-700/50 transition-colors"
                title="Перезапустить"
                on:click={() => restart(tunnel.id)}
              >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/>
                </svg>
              </button>
              <button
                class="p-1.5 rounded-md text-zinc-400 hover:text-red-400 hover:bg-zinc-700/50 transition-colors"
                title="Отключить"
                on:click={() => disconnect(tunnel.id)}
              >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M10 9V5l-7 7 7 7v-4.1c5 0 8.5 1.6 11 5.1-1-5-4-10-11-11z"/>
                </svg>
              </button>
            {:else if tunnel.state === 'down' || tunnel.state === 'error'}
              <button
                class="p-1.5 rounded-md text-zinc-400 hover:text-green-400 hover:bg-zinc-700/50 transition-colors"
                title="Подключить"
                on:click={() => connect(tunnel.id)}
              >
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M8 5v14l11-7z"/>
                </svg>
              </button>
            {/if}
            <button
              class="p-1.5 rounded-md text-zinc-400 hover:text-red-400 hover:bg-zinc-700/50 transition-colors"
              title="Удалить"
              on:click={() => remove(tunnel.id)}
            >
              <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/>
              </svg>
            </button>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

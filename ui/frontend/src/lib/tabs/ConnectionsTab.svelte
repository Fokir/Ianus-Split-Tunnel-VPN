<script>
  import { onMount, onDestroy, tick } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import * as api from '../api.js';
  import { countryFlagUrl, formatSpeed, formatBytes, sortTunnels } from '../utils.js';
  import ErrorAlert from '../ErrorAlert.svelte';
  import { Spinner, EmptyState } from '../components';
  import { t } from '../i18n';
  import TunnelFormModal from './connections/TunnelFormModal.svelte';
  import VlessUriModal from './connections/VlessUriModal.svelte';

  let tunnels = [];
  let loading = true;
  let error = '';
  let showAddMenu = false;

  // Stats map: tunnelId → { speedTx, speedRx, bytesTx, bytesRx, ... }
  let statsMap = {};
  let statsUnsub;

  // Form modal
  let showFormModal = false;
  let formModalProtocol = '';

  // URI modal
  let showUriModal = false;

  // Inline rename
  let renamingId = '';
  let renameValue = '';
  let renameInput;

  // Delete confirmation
  let confirmRemoveId = '';

  // Drag & drop reorder
  let dragIndex = -1;
  let dragOverIndex = -1;

  function handleDragStart(e, index) {
    dragIndex = index;
    e.dataTransfer.effectAllowed = 'move';
    e.dataTransfer.setData('text/plain', String(index));
    e.currentTarget.style.opacity = '0.4';
  }

  function handleDragEnd(e) {
    e.currentTarget.style.opacity = '';
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

  async function handleDrop(e, index) {
    e.preventDefault();
    if (dragIndex < 0 || dragIndex === index) {
      dragIndex = -1;
      dragOverIndex = -1;
      return;
    }
    const reordered = [...tunnels];
    const [moved] = reordered.splice(dragIndex, 1);
    reordered.splice(index, 0, moved);
    tunnels = reordered;
    dragIndex = -1;
    dragOverIndex = -1;

    try {
      await api.saveTunnelOrder(tunnels.map(t => t.id));
    } catch (e) {
      error = e.message;
    }
  }

  onMount(async () => {
    await refresh();
    api.startStatsStream();

    statsUnsub = Events.On('stats-update', (event) => {
      const snap = event.data;
      if (!snap || !snap.tunnels) return;
      const newMap = { ...statsMap };
      for (const s of snap.tunnels) {
        newMap[s.tunnelId] = {
          speedTx: s.speedTx || 0, speedRx: s.speedRx || 0,
          bytesTx: s.bytesTx || 0, bytesRx: s.bytesRx || 0,
          packetLoss: s.packetLoss || 0, latencyMs: s.latencyMs || 0, jitterMs: s.jitterMs || 0,
        };
      }
      statsMap = newMap;
    });
  });

  onDestroy(() => {
    if (statsUnsub) statsUnsub();
  });

  async function refresh() {
    loading = true;
    error = '';
    try {
      const list = (await api.listTunnels() || []).filter(t => t.id !== '__direct__');
      tunnels = sortTunnels(list);
    } catch (e) {
      error = e.message || $t('connections.failedToLoad');
    } finally {
      loading = false;
    }
  }

  async function connect(id) {
    try { await api.connectTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function disconnect(id) {
    try { await api.disconnectTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function restart(id) {
    try { await api.restartTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function remove(id) {
    confirmRemoveId = '';
    try { await api.removeTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function connectAllTunnels() {
    try { await api.connectAll(); await refresh(); } catch (e) { error = e.message; }
  }
  async function disconnectAllTunnels() {
    try { await api.disconnectAll(); await refresh(); } catch (e) { error = e.message; }
  }

  // File-based tunnel add (AWG / WG)
  let fileInput;
  let fileProtocol = 'amneziawg';

  async function handleAddFile(protocol) {
    showAddMenu = false;
    fileProtocol = protocol;
    await tick();
    fileInput.click();
  }

  async function handleFileSelected(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (ev) => {
      const data = new Uint8Array(ev.target.result);
      const name = file.name.replace(/\.(conf|json)$/i, '');
      try {
        await api.addTunnel({ id: '', protocol: fileProtocol, name, settings: {}, configFileData: Array.from(data) });
        await refresh();
      } catch (err) {
        error = err.message;
      }
    };
    reader.readAsArrayBuffer(file);
    e.target.value = '';
  }

  function openFormModal(protocol) {
    showAddMenu = false;
    formModalProtocol = protocol;
    showFormModal = true;
  }

  function openUriModal() {
    showAddMenu = false;
    showUriModal = true;
  }

  async function handleTunnelAdded() {
    showFormModal = false;
    showUriModal = false;
    await refresh();
  }

  async function startRename(tunnel) {
    renamingId = tunnel.id;
    renameValue = tunnel.name || tunnel.id;
    await tick();
    if (renameInput) { renameInput.focus(); renameInput.select(); }
  }

  async function saveRename() {
    if (!renamingId) return;
    const trimmed = renameValue.trim();
    if (trimmed) {
      try {
        await api.renameTunnel(renamingId, trimmed);
        await refresh();
      } catch (e) { error = e.message; }
    }
    renamingId = '';
    renameValue = '';
  }

  function cancelRename() { renamingId = ''; renameValue = ''; }

  function handleRenameKeydown(e) {
    if (e.key === 'Enter') { e.preventDefault(); saveRename(); }
    else if (e.key === 'Escape') { e.preventDefault(); cancelRename(); }
  }

  function protocolLabel(proto) {
    switch (proto) {
      case 'amneziawg': return 'AWG';
      case 'wireguard': return 'WG';
      case 'socks5': return 'SOCKS5';
      case 'httpproxy': return 'HTTP';
      case 'vless': return 'VLESS';
      default: return proto.toUpperCase();
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
    <h2 class="text-lg font-semibold text-zinc-100">{$t('connections.title')}</h2>
    <div class="flex items-center gap-2">
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-green-600/20 text-green-400 hover:bg-green-600/30 transition-colors"
        on:click={connectAllTunnels}
      >
        {$t('connections.connectAll')}
      </button>
      <button
        class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
        on:click={disconnectAllTunnels}
      >
        {$t('connections.disconnectAll')}
      </button>
      <div class="relative">
        <button
          class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600/20 text-blue-400 hover:bg-blue-600/30 transition-colors"
          on:click={() => showAddMenu = !showAddMenu}
        >
          {$t('connections.add')}
        </button>
        {#if showAddMenu}
          <div class="absolute right-0 top-full mt-1 w-52 bg-zinc-800 border border-zinc-700 rounded-lg shadow-xl z-10 py-1">
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={() => handleAddFile('amneziawg')}>
              AmneziaWG (.conf)
            </button>
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={() => handleAddFile('wireguard')}>
              WireGuard (.conf)
            </button>
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={() => handleAddFile('vless')}>
              VLESS Xray (.json)
            </button>
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={openUriModal}>
              {$t('connections.vlessLink')}
            </button>
            <div class="border-t border-zinc-700 my-1"></div>
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={() => openFormModal('socks5')}>
              SOCKS5
            </button>
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={() => openFormModal('httpproxy')}>
              HTTP Proxy
            </button>
            <button class="w-full px-3 py-2 text-left text-sm text-zinc-200 hover:bg-zinc-700/50 transition-colors"
              on:click={() => openFormModal('vless')}>
              VLESS (Xray)
            </button>
          </div>
        {/if}
      </div>
    </div>
  </div>

  <input
    bind:this={fileInput}
    type="file"
    accept={fileProtocol === 'vless' ? '.json' : '.conf'}
    class="hidden"
    on:change={handleFileSelected}
  />

  {#if error}
    <ErrorAlert message={error} />
  {/if}

  {#if loading}
    <div class="py-12">
      <Spinner text={$t('connections.loading')} />
    </div>
  {:else if tunnels.length === 0}
    <EmptyState title={$t('connections.noTunnels')} description={$t('connections.noTunnelsHint')}>
      <svg slot="icon" class="w-12 h-12" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
      </svg>
    </EmptyState>
  {:else}
    <!-- Tunnel list -->
    <div class="space-y-2">
      {#each tunnels as tunnel, i}
        {@const stats = statsMap[tunnel.id]}
        <div
          class="p-3 bg-zinc-800/50 border rounded-lg hover:bg-zinc-800/70 transition-colors
                 {dragOverIndex === i && dragIndex !== i ? 'border-blue-500/50 bg-zinc-800/80' : 'border-zinc-700/40'}"
          draggable="true"
          on:dragstart={(e) => handleDragStart(e, i)}
          on:dragend={handleDragEnd}
          on:dragover={(e) => handleDragOver(e, i)}
          on:dragleave={handleDragLeave}
          on:drop={(e) => handleDrop(e, i)}
          role="listitem"
        >
          <!-- Row 1: drag handle, status dot, name, protocol badge, flag+IP, buttons -->
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2.5 min-w-0">
              <span class="cursor-grab text-zinc-600 hover:text-zinc-400 shrink-0" title={$t('connections.dragToReorder')}>
                <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M11 18c0 1.1-.9 2-2 2s-2-.9-2-2 .9-2 2-2 2 .9 2 2zm-2-8c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0-6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm6 4c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/>
                </svg>
              </span>
              <span class="w-2 h-2 rounded-full shrink-0 {stateDot(tunnel.state)}"></span>
              {#if renamingId === tunnel.id}
                <input
                  bind:this={renameInput}
                  bind:value={renameValue}
                  on:blur={saveRename}
                  on:keydown={handleRenameKeydown}
                  class="text-sm font-medium text-zinc-200 bg-zinc-700 border border-blue-500 rounded px-1.5 py-0.5 outline-none min-w-[80px] max-w-[200px]"
                />
              {:else}
                <!-- svelte-ignore a11y-no-static-element-interactions -->
                <span
                  class="text-sm font-medium text-zinc-200 truncate cursor-default"
                  on:dblclick={() => startRename(tunnel)}
                  title={$t('connections.clickToRename')}
                >
                  {tunnel.name || tunnel.id}
                </span>
              {/if}
              <span class="px-1.5 py-0.5 text-[0.625rem] font-medium rounded bg-zinc-700/60 text-zinc-400 shrink-0 leading-none">
                {protocolLabel(tunnel.protocol)}
              </span>
              {#if tunnel.externalIp}
                <span class="text-xs text-zinc-500 shrink-0 flex items-center gap-1">
                  {#if tunnel.countryCode}
                    {@const flagUrl = countryFlagUrl(tunnel.countryCode)}
                    {#if flagUrl}
                      <img src={flagUrl} alt={tunnel.countryCode} class="w-5 h-[15px] object-cover rounded-[2px]"
                           on:error={(e) => { e.target.style.display = 'none'; e.target.nextElementSibling.style.display = ''; }}
                      />
                      <span class="text-[0.625rem] text-zinc-600 font-medium" style="display:none">{tunnel.countryCode}</span>
                    {:else}
                      <span class="text-[0.625rem] text-zinc-600 font-medium">{tunnel.countryCode}</span>
                    {/if}
                  {/if}
                  {tunnel.externalIp}
                </span>
              {/if}
            </div>

            <div class="flex items-center gap-1 shrink-0">
              {#if tunnel.state === 'up'}
                <button class="p-1.5 rounded-md text-zinc-400 hover:text-yellow-400 hover:bg-zinc-700/50 transition-colors" title={$t('connections.restart')} on:click={() => restart(tunnel.id)}>
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M17.65 6.35A7.958 7.958 0 0012 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08A5.99 5.99 0 0112 18c-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>
                </button>
                <button class="p-1.5 rounded-md text-zinc-400 hover:text-red-400 hover:bg-zinc-700/50 transition-colors" title={$t('connections.disconnect')} on:click={() => disconnect(tunnel.id)}>
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M13 3h-2v10h2V3zm4.83 2.17l-1.42 1.42C17.99 7.86 19 9.81 19 12c0 3.87-3.13 7-7 7s-7-3.13-7-7c0-2.19 1.01-4.14 2.58-5.42L6.17 5.17C4.23 6.82 3 9.26 3 12c0 4.97 4.03 9 9 9s9-4.03 9-9c0-2.74-1.23-5.18-3.17-6.83z"/></svg>
                </button>
              {:else if tunnel.state === 'down' || tunnel.state === 'error'}
                <button class="p-1.5 rounded-md text-zinc-400 hover:text-green-400 hover:bg-zinc-700/50 transition-colors" title={$t('connections.connect')} on:click={() => connect(tunnel.id)}>
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
                </button>
              {/if}
              {#if confirmRemoveId === tunnel.id}
                <div class="flex items-center gap-1 ml-1">
                  <button class="px-2 py-1 text-xs rounded bg-red-600/30 text-red-400 hover:bg-red-600/50 transition-colors" on:click={() => remove(tunnel.id)}>{$t('connections.yes')}</button>
                  <button class="px-2 py-1 text-xs rounded bg-zinc-700/50 text-zinc-400 hover:bg-zinc-700 transition-colors" on:click={() => { confirmRemoveId = ''; }}>{$t('connections.no')}</button>
                </div>
              {:else}
                <button class="p-1.5 rounded-md text-zinc-400 hover:text-red-400 hover:bg-zinc-700/50 transition-colors" title={$t('connections.remove')} on:click={() => { confirmRemoveId = tunnel.id; }}>
                  <svg class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
                </button>
              {/if}
            </div>
          </div>

          <!-- Row 2: Error or Stats -->
          {#if tunnel.error}
            <div class="mt-1 ml-[2.125rem] text-xs text-red-400 truncate">{tunnel.error}</div>
          {/if}
          {#if tunnel.state === 'up' && stats}
            <div class="mt-1.5 ml-[2.125rem] flex items-center gap-4 text-xs text-zinc-500 font-mono tabular-nums">
              <span class="inline-flex items-center gap-1"><span class="text-green-400/70">&uarr;</span><span>{formatSpeed(stats.speedTx)}</span></span>
              <span class="inline-flex items-center gap-1"><span class="text-blue-400/70">&darr;</span><span>{formatSpeed(stats.speedRx)}</span></span>
              <span class="text-zinc-600">|</span>
              <span class="inline-flex items-center gap-1"><span class="text-green-400/70">&uarr;</span><span>{formatBytes(stats.bytesTx)}</span></span>
              <span class="inline-flex items-center gap-1"><span class="text-blue-400/70">&darr;</span><span>{formatBytes(stats.bytesRx)}</span></span>
            </div>
          {/if}
          {#if confirmRemoveId === tunnel.id}
            <div class="mt-1.5 ml-[2.125rem] text-xs text-zinc-500">{$t('connections.confirmRemoveHint')}</div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<!-- Tunnel form modal (SOCKS5/HTTP/VLESS) -->
<TunnelFormModal open={showFormModal} protocol={formModalProtocol}
  on:close={() => { showFormModal = false; }}
  on:added={handleTunnelAdded}
/>

<!-- VLESS URI paste modal -->
<VlessUriModal open={showUriModal}
  on:close={() => { showUriModal = false; }}
  on:added={handleTunnelAdded}
/>

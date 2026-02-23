<script>
  import { onMount, tick } from 'svelte';
  import * as api from '../api.js';
  import ErrorAlert from '../ErrorAlert.svelte';

  let tunnels = [];
  let loading = true;
  let error = '';
  let showAddMenu = false;

  // Modal state
  let showModal = false;
  let modalProtocol = '';
  let modalName = '';
  let modalSaving = false;

  // SOCKS5 fields
  let socks5Server = '';
  let socks5Port = '1080';
  let socks5Username = '';
  let socks5Password = '';
  let socks5UdpEnabled = true;

  // HTTP Proxy fields
  let httpServer = '';
  let httpPort = '8080';
  let httpUsername = '';
  let httpPassword = '';
  let httpTls = false;
  let httpTlsSkipVerify = false;

  // Modal error (shown inside modal, not on tab)
  let modalError = '';
  let uriError = '';

  // VLESS URI paste modal
  let showUriModal = false;
  let uriValue = '';
  let uriSaving = false;

  // VLESS fields
  let vlessAddress = '';
  let vlessPort = '443';
  let vlessUuid = '';
  let vlessFlow = 'xtls-rprx-vision';
  let vlessSecurity = 'reality';
  let vlessNetwork = 'tcp';
  let vlessRealityPublicKey = '';
  let vlessRealityShortId = '';
  let vlessRealityServerName = '';
  let vlessRealityFingerprint = 'chrome';
  let vlessTlsServerName = '';
  let vlessTlsFingerprint = 'chrome';
  let vlessTlsAllowInsecure = false;
  let vlessWsPath = '';
  let vlessWsHost = '';
  let vlessGrpcServiceName = '';
  let vlessXhttpPath = '';
  let vlessXhttpHost = '';
  let vlessXhttpMode = 'auto';

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
    try { await api.connectTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function disconnect(id) {
    try { await api.disconnectTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function restart(id) {
    try { await api.restartTunnel(id); await refresh(); } catch (e) { error = e.message; }
  }
  async function remove(id) {
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
    await tick(); // wait for accept attribute to update
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
        await api.addTunnel({
          id: '',
          protocol: fileProtocol,
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

  // URI-based tunnel add (vless:// link)
  function openUriModal() {
    showAddMenu = false;
    uriValue = '';
    uriSaving = false;
    uriError = '';
    showUriModal = true;
  }

  async function saveUri() {
    const uri = uriValue.trim();
    if (!uri) { uriError = 'Вставьте ссылку vless://'; return; }
    if (!uri.startsWith('vless://')) { uriError = 'Ссылка должна начинаться с vless://'; return; }
    uriSaving = true;
    uriError = '';
    try {
      const data = new TextEncoder().encode(uri);
      await api.addTunnel({
        id: '',
        protocol: 'vless',
        name: '',
        settings: {},
        configFileData: Array.from(data),
      });
      showUriModal = false;
      await refresh();
    } catch (err) {
      uriError = err.message;
    } finally {
      uriSaving = false;
    }
  }

  // Form-based tunnel add
  function openFormModal(protocol) {
    showAddMenu = false;
    modalProtocol = protocol;
    modalName = '';
    modalSaving = false;
    modalError = '';
    resetFormFields();
    showModal = true;
  }

  function resetFormFields() {
    socks5Server = ''; socks5Port = '1080'; socks5Username = ''; socks5Password = ''; socks5UdpEnabled = true;
    httpServer = ''; httpPort = '8080'; httpUsername = ''; httpPassword = ''; httpTls = false; httpTlsSkipVerify = false;
    vlessAddress = ''; vlessPort = '443'; vlessUuid = ''; vlessFlow = 'xtls-rprx-vision';
    vlessSecurity = 'reality'; vlessNetwork = 'tcp';
    vlessRealityPublicKey = ''; vlessRealityShortId = ''; vlessRealityServerName = ''; vlessRealityFingerprint = 'chrome';
    vlessTlsServerName = ''; vlessTlsFingerprint = 'chrome'; vlessTlsAllowInsecure = false;
    vlessWsPath = ''; vlessWsHost = ''; vlessGrpcServiceName = '';
    vlessXhttpPath = ''; vlessXhttpHost = ''; vlessXhttpMode = 'auto';
  }

  function closeModal() {
    showModal = false;
  }

  async function saveModal() {
    if (!modalName.trim()) { modalError = 'Введите имя туннеля'; return; }
    modalSaving = true;
    modalError = '';

    let settings = {};
    try {
      if (modalProtocol === 'socks5') {
        if (!socks5Server) { modalError = 'Укажите адрес сервера'; modalSaving = false; return; }
        settings = {
          server: socks5Server,
          port: socks5Port,
          username: socks5Username,
          password: socks5Password,
          udp_enabled: socks5UdpEnabled ? 'true' : 'false',
        };
      } else if (modalProtocol === 'httpproxy') {
        if (!httpServer) { modalError = 'Укажите адрес сервера'; modalSaving = false; return; }
        settings = {
          server: httpServer,
          port: httpPort,
          username: httpUsername,
          password: httpPassword,
          tls: httpTls ? 'true' : 'false',
          tls_skip_verify: httpTlsSkipVerify ? 'true' : 'false',
        };
      } else if (modalProtocol === 'vless') {
        if (!vlessAddress) { modalError = 'Укажите адрес сервера'; modalSaving = false; return; }
        if (!vlessUuid) { modalError = 'Укажите UUID'; modalSaving = false; return; }
        settings = {
          address: vlessAddress,
          port: vlessPort,
          uuid: vlessUuid,
          flow: vlessFlow,
          security: vlessSecurity,
          network: vlessNetwork,
        };
        if (vlessSecurity === 'reality') {
          settings['reality.public_key'] = vlessRealityPublicKey;
          settings['reality.short_id'] = vlessRealityShortId;
          settings['reality.server_name'] = vlessRealityServerName;
          settings['reality.fingerprint'] = vlessRealityFingerprint;
        } else if (vlessSecurity === 'tls') {
          settings['tls.server_name'] = vlessTlsServerName;
          settings['tls.fingerprint'] = vlessTlsFingerprint;
          settings['tls.allow_insecure'] = vlessTlsAllowInsecure ? 'true' : 'false';
        }
        if (vlessNetwork === 'ws') {
          settings['ws.path'] = vlessWsPath;
          if (vlessWsHost) settings['ws.headers.Host'] = vlessWsHost;
        } else if (vlessNetwork === 'grpc') {
          settings['grpc.service_name'] = vlessGrpcServiceName;
        } else if (vlessNetwork === 'xhttp') {
          settings['xhttp.path'] = vlessXhttpPath;
          if (vlessXhttpHost) settings['xhttp.host'] = vlessXhttpHost;
          if (vlessXhttpMode) settings['xhttp.mode'] = vlessXhttpMode;
        }
      }

      await api.addTunnel({
        id: '',
        protocol: modalProtocol,
        name: modalName.trim(),
        settings: settings,
        configFileData: [],
      });
      showModal = false;
      await refresh();
    } catch (err) {
      modalError = err.message;
    } finally {
      modalSaving = false;
    }
  }

  function protocolLabel(proto) {
    switch (proto) {
      case 'amneziawg': return 'AmneziaWG';
      case 'wireguard': return 'WireGuard';
      case 'socks5': return 'SOCKS5';
      case 'httpproxy': return 'HTTP Proxy';
      case 'vless': return 'VLESS';
      default: return proto.toUpperCase();
    }
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
          on:click={() => showAddMenu = !showAddMenu}
        >
          + Добавить
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
              VLESS (vless:// ссылка)
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

  <!-- Error -->
  {#if error}
    <ErrorAlert message={error} />
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
                <span>{protocolLabel(tunnel.protocol)}</span>
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

<!-- Modal for form-based tunnel add -->
{#if showModal}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
    on:click|self={closeModal}
    on:keydown={(e) => e.key === 'Escape' && closeModal()}
    role="presentation">
    <div class="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-md mx-4 max-h-[85vh] overflow-y-auto">
      <div class="flex items-center justify-between px-5 py-4 border-b border-zinc-700">
        <h3 class="text-base font-semibold text-zinc-100">{protocolLabel(modalProtocol)}</h3>
        <button class="text-zinc-400 hover:text-zinc-200" on:click={closeModal}>
          <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
        </button>
      </div>

      <div class="px-5 py-4 space-y-3">
        {#if modalError}
          <ErrorAlert message={modalError} />
        {/if}
        <!-- Name (common) -->
        <div>
          <label for="tunnel-name" class="block text-xs font-medium text-zinc-400 mb-1">Имя</label>
          <input id="tunnel-name" type="text" bind:value={modalName} placeholder="Мой туннель"
            class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
        </div>

        <!-- SOCKS5 form -->
        {#if modalProtocol === 'socks5'}
          <div>
            <label for="s5-server" class="block text-xs font-medium text-zinc-400 mb-1">Сервер</label>
            <input id="s5-server" type="text" bind:value={socks5Server} placeholder="proxy.example.com"
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
          </div>
          <div>
            <label for="s5-port" class="block text-xs font-medium text-zinc-400 mb-1">Порт</label>
            <input id="s5-port" type="text" bind:value={socks5Port} placeholder="1080"
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="s5-user" class="block text-xs font-medium text-zinc-400 mb-1">Логин</label>
              <input id="s5-user" type="text" bind:value={socks5Username} placeholder="(необязательно)"
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
            </div>
            <div>
              <label for="s5-pass" class="block text-xs font-medium text-zinc-400 mb-1">Пароль</label>
              <input id="s5-pass" type="password" bind:value={socks5Password} placeholder="(необязательно)"
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
            </div>
          </div>
          <label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
            <input type="checkbox" bind:checked={socks5UdpEnabled} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
            UDP ASSOCIATE
          </label>

        <!-- HTTP Proxy form -->
        {:else if modalProtocol === 'httpproxy'}
          <div>
            <label for="http-server" class="block text-xs font-medium text-zinc-400 mb-1">Сервер</label>
            <input id="http-server" type="text" bind:value={httpServer} placeholder="proxy.corp.com"
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
          </div>
          <div>
            <label for="http-port" class="block text-xs font-medium text-zinc-400 mb-1">Порт</label>
            <input id="http-port" type="text" bind:value={httpPort} placeholder="8080"
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="http-user" class="block text-xs font-medium text-zinc-400 mb-1">Логин</label>
              <input id="http-user" type="text" bind:value={httpUsername} placeholder="(необязательно)"
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
            </div>
            <div>
              <label for="http-pass" class="block text-xs font-medium text-zinc-400 mb-1">Пароль</label>
              <input id="http-pass" type="password" bind:value={httpPassword} placeholder="(необязательно)"
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
            </div>
          </div>
          <label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
            <input type="checkbox" bind:checked={httpTls} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
            TLS (HTTPS Proxy)
          </label>
          {#if httpTls}
            <label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer ml-5">
              <input type="checkbox" bind:checked={httpTlsSkipVerify} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
              Не проверять сертификат
            </label>
          {/if}
          <div class="px-3 py-2 text-xs bg-yellow-900/20 border border-yellow-800/30 rounded-lg text-yellow-400">
            HTTP Proxy не поддерживает UDP. Игры, VoIP и QUIC могут не работать.
          </div>

        <!-- VLESS form -->
        {:else if modalProtocol === 'vless'}
          <div class="grid grid-cols-3 gap-3">
            <div class="col-span-2">
              <label for="vless-addr" class="block text-xs font-medium text-zinc-400 mb-1">Адрес</label>
              <input id="vless-addr" type="text" bind:value={vlessAddress} placeholder="server.example.com"
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
            </div>
            <div>
              <label for="vless-port" class="block text-xs font-medium text-zinc-400 mb-1">Порт</label>
              <input id="vless-port" type="text" bind:value={vlessPort} placeholder="443"
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
            </div>
          </div>
          <div>
            <label for="vless-uuid" class="block text-xs font-medium text-zinc-400 mb-1">UUID</label>
            <input id="vless-uuid" type="text" bind:value={vlessUuid} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none" />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label for="vless-flow" class="block text-xs font-medium text-zinc-400 mb-1">Flow</label>
              <select id="vless-flow" bind:value={vlessFlow}
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
                <option value="">Нет</option>
                <option value="xtls-rprx-vision">xtls-rprx-vision</option>
              </select>
            </div>
            <div>
              <label for="vless-network" class="block text-xs font-medium text-zinc-400 mb-1">Транспорт</label>
              <select id="vless-network" bind:value={vlessNetwork}
                class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
                <option value="tcp">TCP</option>
                <option value="ws">WebSocket</option>
                <option value="grpc">gRPC</option>
                <option value="xhttp">XHTTP (SplitHTTP)</option>
              </select>
            </div>
          </div>
          <div>
            <label for="vless-security" class="block text-xs font-medium text-zinc-400 mb-1">Безопасность</label>
            <select id="vless-security" bind:value={vlessSecurity}
              class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
              <option value="reality">Reality</option>
              <option value="tls">TLS</option>
              <option value="none">Нет</option>
            </select>
          </div>

          <!-- Reality settings -->
          {#if vlessSecurity === 'reality'}
            <div class="pl-3 border-l-2 border-blue-500/30 space-y-3">
              <p class="text-xs font-medium text-blue-400">Reality</p>
              <div>
                <label for="vless-rpk" class="block text-xs font-medium text-zinc-400 mb-1">Public Key</label>
                <input id="vless-rpk" type="text" bind:value={vlessRealityPublicKey}
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none" />
              </div>
              <div class="grid grid-cols-2 gap-3">
                <div>
                  <label for="vless-rsid" class="block text-xs font-medium text-zinc-400 mb-1">Short ID</label>
                  <input id="vless-rsid" type="text" bind:value={vlessRealityShortId} placeholder="abcdef01"
                    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none" />
                </div>
                <div>
                  <label for="vless-rfp" class="block text-xs font-medium text-zinc-400 mb-1">Fingerprint</label>
                  <select id="vless-rfp" bind:value={vlessRealityFingerprint}
                    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
                    <option value="chrome">Chrome</option>
                    <option value="firefox">Firefox</option>
                    <option value="safari">Safari</option>
                    <option value="random">Random</option>
                  </select>
                </div>
              </div>
              <div>
                <label for="vless-rsn" class="block text-xs font-medium text-zinc-400 mb-1">Server Name (SNI)</label>
                <input id="vless-rsn" type="text" bind:value={vlessRealityServerName} placeholder="www.google.com"
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
            </div>
          {/if}

          <!-- TLS settings -->
          {#if vlessSecurity === 'tls'}
            <div class="pl-3 border-l-2 border-green-500/30 space-y-3">
              <p class="text-xs font-medium text-green-400">TLS</p>
              <div>
                <label for="vless-tsn" class="block text-xs font-medium text-zinc-400 mb-1">Server Name (SNI)</label>
                <input id="vless-tsn" type="text" bind:value={vlessTlsServerName}
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
              <div>
                <label for="vless-tfp" class="block text-xs font-medium text-zinc-400 mb-1">Fingerprint</label>
                <select id="vless-tfp" bind:value={vlessTlsFingerprint}
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
                  <option value="chrome">Chrome</option>
                  <option value="firefox">Firefox</option>
                  <option value="safari">Safari</option>
                </select>
              </div>
              <label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
                <input type="checkbox" bind:checked={vlessTlsAllowInsecure} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
                Не проверять сертификат
              </label>
            </div>
          {/if}

          <!-- WebSocket settings -->
          {#if vlessNetwork === 'ws'}
            <div class="pl-3 border-l-2 border-purple-500/30 space-y-3">
              <p class="text-xs font-medium text-purple-400">WebSocket</p>
              <div>
                <label for="vless-wsp" class="block text-xs font-medium text-zinc-400 mb-1">Path</label>
                <input id="vless-wsp" type="text" bind:value={vlessWsPath} placeholder="/ws"
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
              <div>
                <label for="vless-wsh" class="block text-xs font-medium text-zinc-400 mb-1">Host</label>
                <input id="vless-wsh" type="text" bind:value={vlessWsHost} placeholder="example.com"
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
            </div>
          {/if}

          <!-- gRPC settings -->
          {#if vlessNetwork === 'grpc'}
            <div class="pl-3 border-l-2 border-orange-500/30 space-y-3">
              <p class="text-xs font-medium text-orange-400">gRPC</p>
              <div>
                <label for="vless-gsn" class="block text-xs font-medium text-zinc-400 mb-1">Service Name</label>
                <input id="vless-gsn" type="text" bind:value={vlessGrpcServiceName} placeholder="grpc-service"
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
            </div>
          {/if}

          <!-- XHTTP (SplitHTTP) settings -->
          {#if vlessNetwork === 'xhttp'}
            <div class="pl-3 border-l-2 border-cyan-500/30 space-y-3">
              <p class="text-xs font-medium text-cyan-400">XHTTP (SplitHTTP)</p>
              <div>
                <label for="vless-xhp" class="block text-xs font-medium text-zinc-400 mb-1">Path</label>
                <input id="vless-xhp" type="text" bind:value={vlessXhttpPath} placeholder="/xhttp"
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
              <div>
                <label for="vless-xhh" class="block text-xs font-medium text-zinc-400 mb-1">Host</label>
                <input id="vless-xhh" type="text" bind:value={vlessXhttpHost} placeholder="example.com"
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
              </div>
              <div>
                <label for="vless-xhm" class="block text-xs font-medium text-zinc-400 mb-1">Режим</label>
                <select id="vless-xhm" bind:value={vlessXhttpMode}
                  class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
                  <option value="auto">auto</option>
                  <option value="packet-up">packet-up</option>
                  <option value="stream-up">stream-up</option>
                  <option value="stream-one">stream-one</option>
                </select>
              </div>
            </div>
          {/if}
        {/if}
      </div>

      <!-- Modal footer -->
      <div class="flex justify-end gap-2 px-5 py-4 border-t border-zinc-700">
        <button
          class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
          on:click={closeModal}
        >
          Отмена
        </button>
        <button
          class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          disabled={modalSaving}
          on:click={saveModal}
        >
          {modalSaving ? 'Сохранение...' : 'Добавить'}
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- URI paste modal -->
{#if showUriModal}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
    on:click|self={() => { showUriModal = false; }}
    on:keydown={(e) => e.key === 'Escape' && (showUriModal = false)}
    role="presentation">
    <div class="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4">
      <div class="flex items-center justify-between px-5 py-4 border-b border-zinc-700">
        <h3 class="text-base font-semibold text-zinc-100">VLESS — импорт из ссылки</h3>
        <button class="text-zinc-400 hover:text-zinc-200" on:click={() => { showUriModal = false; }}>
          <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
        </button>
      </div>
      <div class="px-5 py-4 space-y-3">
        {#if uriError}
          <ErrorAlert message={uriError} />
        {/if}
        <div>
          <label for="vless-uri" class="block text-xs font-medium text-zinc-400 mb-1">Ссылка vless://</label>
          <textarea
            id="vless-uri"
            bind:value={uriValue}
            placeholder="vless://uuid@host:port?type=tcp&security=reality&..."
            rows="3"
            class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none resize-none"
          ></textarea>
        </div>
        <p class="text-xs text-zinc-500">Имя туннеля будет взято из фрагмента ссылки (#name) или сгенерировано автоматически.</p>
      </div>
      <div class="flex justify-end gap-2 px-5 py-4 border-t border-zinc-700">
        <button
          class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
          on:click={() => { showUriModal = false; }}
        >
          Отмена
        </button>
        <button
          class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
          disabled={uriSaving}
          on:click={saveUri}
        >
          {uriSaving ? 'Импорт...' : 'Импортировать'}
        </button>
      </div>
    </div>
  </div>
{/if}

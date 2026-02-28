<script>
  import { createEventDispatcher } from 'svelte';
  import * as api from '../../api.js';
  import ErrorAlert from '../../ErrorAlert.svelte';
  import { Modal } from '../../components';
  import { t } from '../../i18n';
  import Socks5Form from './forms/Socks5Form.svelte';
  import HttpProxyForm from './forms/HttpProxyForm.svelte';
  import VlessForm from './forms/VlessForm.svelte';

  export let open = false;
  export let protocol = '';

  const dispatch = createEventDispatcher();

  let modalName = '';
  let modalSaving = false;
  let modalError = '';

  // SOCKS5
  let socks5Server = '', socks5Port = '1080', socks5Username = '', socks5Password = '', socks5UdpEnabled = true;
  // HTTP Proxy
  let httpServer = '', httpPort = '8080', httpUsername = '', httpPassword = '', httpTls = false, httpTlsSkipVerify = false;
  // VLESS
  let vlessAddress = '', vlessPort = '443', vlessUuid = '', vlessFlow = 'xtls-rprx-vision';
  let vlessSecurity = 'reality', vlessNetwork = 'tcp';
  let vlessRealityPublicKey = '', vlessRealityShortId = '', vlessRealityServerName = '', vlessRealityFingerprint = 'chrome';
  let vlessTlsServerName = '', vlessTlsFingerprint = 'chrome', vlessTlsAllowInsecure = false;
  let vlessWsPath = '', vlessWsHost = '', vlessGrpcServiceName = '';
  let vlessXhttpPath = '', vlessXhttpHost = '', vlessXhttpMode = 'auto';

  $: if (open) resetAll();

  function resetAll() {
    modalName = ''; modalSaving = false; modalError = '';
    socks5Server = ''; socks5Port = '1080'; socks5Username = ''; socks5Password = ''; socks5UdpEnabled = true;
    httpServer = ''; httpPort = '8080'; httpUsername = ''; httpPassword = ''; httpTls = false; httpTlsSkipVerify = false;
    vlessAddress = ''; vlessPort = '443'; vlessUuid = ''; vlessFlow = 'xtls-rprx-vision';
    vlessSecurity = 'reality'; vlessNetwork = 'tcp';
    vlessRealityPublicKey = ''; vlessRealityShortId = ''; vlessRealityServerName = ''; vlessRealityFingerprint = 'chrome';
    vlessTlsServerName = ''; vlessTlsFingerprint = 'chrome'; vlessTlsAllowInsecure = false;
    vlessWsPath = ''; vlessWsHost = ''; vlessGrpcServiceName = '';
    vlessXhttpPath = ''; vlessXhttpHost = ''; vlessXhttpMode = 'auto';
  }

  function protocolLabelFull(proto) {
    switch (proto) {
      case 'amneziawg': return 'AmneziaWG';
      case 'wireguard': return 'WireGuard';
      case 'socks5': return 'SOCKS5';
      case 'httpproxy': return 'HTTP Proxy';
      case 'vless': return 'VLESS';
      default: return proto.toUpperCase();
    }
  }

  function close() {
    dispatch('close');
  }

  async function save() {
    if (!modalName.trim()) { modalError = $t('connections.nameRequired'); return; }
    modalSaving = true;
    modalError = '';

    let settings = {};
    try {
      if (protocol === 'socks5') {
        if (!socks5Server) { modalError = $t('connections.serverRequired'); modalSaving = false; return; }
        settings = {
          server: socks5Server, port: socks5Port,
          username: socks5Username, password: socks5Password,
          udp_enabled: socks5UdpEnabled ? 'true' : 'false',
        };
      } else if (protocol === 'httpproxy') {
        if (!httpServer) { modalError = $t('connections.serverRequired'); modalSaving = false; return; }
        settings = {
          server: httpServer, port: httpPort,
          username: httpUsername, password: httpPassword,
          tls: httpTls ? 'true' : 'false',
          tls_skip_verify: httpTlsSkipVerify ? 'true' : 'false',
        };
      } else if (protocol === 'vless') {
        if (!vlessAddress) { modalError = $t('connections.serverRequired'); modalSaving = false; return; }
        if (!vlessUuid) { modalError = $t('connections.uuidRequired'); modalSaving = false; return; }
        settings = {
          address: vlessAddress, port: vlessPort, uuid: vlessUuid,
          flow: vlessFlow, security: vlessSecurity, network: vlessNetwork,
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
        id: '', protocol, name: modalName.trim(), settings, configFileData: [],
      });
      dispatch('added');
    } catch (err) {
      modalError = err.message;
    } finally {
      modalSaving = false;
    }
  }
</script>

<Modal {open} title={protocolLabelFull(protocol)} on:close={close}>
  <div class="space-y-3">
    {#if modalError}
      <ErrorAlert message={modalError} />
    {/if}
    <!-- Name (common) -->
    <div>
      <label for="tunnel-name" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.name')}</label>
      <input id="tunnel-name" type="text" bind:value={modalName} placeholder={$t('connections.namePlaceholder')}
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>

    {#if protocol === 'socks5'}
      <Socks5Form bind:server={socks5Server} bind:port={socks5Port}
        bind:username={socks5Username} bind:password={socks5Password} bind:udpEnabled={socks5UdpEnabled} />
    {:else if protocol === 'httpproxy'}
      <HttpProxyForm bind:server={httpServer} bind:port={httpPort}
        bind:username={httpUsername} bind:password={httpPassword} bind:tls={httpTls} bind:tlsSkipVerify={httpTlsSkipVerify} />
    {:else if protocol === 'vless'}
      <VlessForm bind:address={vlessAddress} bind:port={vlessPort} bind:uuid={vlessUuid}
        bind:flow={vlessFlow} bind:security={vlessSecurity} bind:network={vlessNetwork}
        bind:realityPublicKey={vlessRealityPublicKey} bind:realityShortId={vlessRealityShortId}
        bind:realityServerName={vlessRealityServerName} bind:realityFingerprint={vlessRealityFingerprint}
        bind:tlsServerName={vlessTlsServerName} bind:tlsFingerprint={vlessTlsFingerprint} bind:tlsAllowInsecure={vlessTlsAllowInsecure}
        bind:wsPath={vlessWsPath} bind:wsHost={vlessWsHost} bind:grpcServiceName={vlessGrpcServiceName}
        bind:xhttpPath={vlessXhttpPath} bind:xhttpHost={vlessXhttpHost} bind:xhttpMode={vlessXhttpMode} />
    {/if}
  </div>

  <svelte:fragment slot="footer">
    <button
      class="px-4 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors"
      on:click={close}
    >
      {$t('connections.cancel')}
    </button>
    <button
      class="px-4 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-50"
      disabled={modalSaving}
      on:click={save}
    >
      {modalSaving ? $t('connections.saving') : $t('connections.addBtn')}
    </button>
  </svelte:fragment>
</Modal>

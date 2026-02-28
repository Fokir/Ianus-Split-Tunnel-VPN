<script>
  import { t } from '../../../i18n';

  export let address = '';
  export let port = '443';
  export let uuid = '';
  export let flow = 'xtls-rprx-vision';
  export let security = 'reality';
  export let network = 'tcp';
  export let realityPublicKey = '';
  export let realityShortId = '';
  export let realityServerName = '';
  export let realityFingerprint = 'chrome';
  export let tlsServerName = '';
  export let tlsFingerprint = 'chrome';
  export let tlsAllowInsecure = false;
  export let wsPath = '';
  export let wsHost = '';
  export let grpcServiceName = '';
  export let xhttpPath = '';
  export let xhttpHost = '';
  export let xhttpMode = 'auto';
</script>

<div class="grid grid-cols-3 gap-3">
  <div class="col-span-2">
    <label for="vless-addr" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.address')}</label>
    <input id="vless-addr" type="text" bind:value={address} placeholder="server.example.com"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="vless-port" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.port')}</label>
    <input id="vless-port" type="text" bind:value={port} placeholder="443"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<div>
  <label for="vless-uuid" class="block text-xs font-medium text-zinc-400 mb-1">UUID</label>
  <input id="vless-uuid" type="text" bind:value={uuid} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none" />
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="vless-flow" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.flow')}</label>
    <select id="vless-flow" bind:value={flow}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
      <option value="">{$t('connections.flowNone')}</option>
      <option value="xtls-rprx-vision">xtls-rprx-vision</option>
    </select>
  </div>
  <div>
    <label for="vless-network" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.transport')}</label>
    <select id="vless-network" bind:value={network}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
      <option value="tcp">TCP</option>
      <option value="ws">WebSocket</option>
      <option value="grpc">gRPC</option>
      <option value="xhttp">XHTTP (SplitHTTP)</option>
    </select>
  </div>
</div>
<div>
  <label for="vless-security" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.security')}</label>
  <select id="vless-security" bind:value={security}
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
    <option value="reality">Reality</option>
    <option value="tls">TLS</option>
    <option value="none">{$t('connections.securityNone')}</option>
  </select>
</div>

<!-- Reality settings -->
{#if security === 'reality'}
  <div class="pl-3 border-l-2 border-blue-500/30 space-y-3">
    <p class="text-xs font-medium text-blue-400">Reality</p>
    <div>
      <label for="vless-rpk" class="block text-xs font-medium text-zinc-400 mb-1">Public Key</label>
      <input id="vless-rpk" type="text" bind:value={realityPublicKey}
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none" />
    </div>
    <div class="grid grid-cols-2 gap-3">
      <div>
        <label for="vless-rsid" class="block text-xs font-medium text-zinc-400 mb-1">Short ID</label>
        <input id="vless-rsid" type="text" bind:value={realityShortId} placeholder="abcdef01"
          class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none" />
      </div>
      <div>
        <label for="vless-rfp" class="block text-xs font-medium text-zinc-400 mb-1">Fingerprint</label>
        <select id="vless-rfp" bind:value={realityFingerprint}
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
      <input id="vless-rsn" type="text" bind:value={realityServerName} placeholder="www.google.com"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
  </div>
{/if}

<!-- TLS settings -->
{#if security === 'tls'}
  <div class="pl-3 border-l-2 border-green-500/30 space-y-3">
    <p class="text-xs font-medium text-green-400">TLS</p>
    <div>
      <label for="vless-tsn" class="block text-xs font-medium text-zinc-400 mb-1">Server Name (SNI)</label>
      <input id="vless-tsn" type="text" bind:value={tlsServerName}
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
    <div>
      <label for="vless-tfp" class="block text-xs font-medium text-zinc-400 mb-1">Fingerprint</label>
      <select id="vless-tfp" bind:value={tlsFingerprint}
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
        <option value="chrome">Chrome</option>
        <option value="firefox">Firefox</option>
        <option value="safari">Safari</option>
      </select>
    </div>
    <label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
      <input type="checkbox" bind:checked={tlsAllowInsecure} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
      {$t('connections.noVerifyCert')}
    </label>
  </div>
{/if}

<!-- WebSocket settings -->
{#if network === 'ws'}
  <div class="pl-3 border-l-2 border-purple-500/30 space-y-3">
    <p class="text-xs font-medium text-purple-400">WebSocket</p>
    <div>
      <label for="vless-wsp" class="block text-xs font-medium text-zinc-400 mb-1">Path</label>
      <input id="vless-wsp" type="text" bind:value={wsPath} placeholder="/ws"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
    <div>
      <label for="vless-wsh" class="block text-xs font-medium text-zinc-400 mb-1">Host</label>
      <input id="vless-wsh" type="text" bind:value={wsHost} placeholder="example.com"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
  </div>
{/if}

<!-- gRPC settings -->
{#if network === 'grpc'}
  <div class="pl-3 border-l-2 border-orange-500/30 space-y-3">
    <p class="text-xs font-medium text-orange-400">gRPC</p>
    <div>
      <label for="vless-gsn" class="block text-xs font-medium text-zinc-400 mb-1">Service Name</label>
      <input id="vless-gsn" type="text" bind:value={grpcServiceName} placeholder="grpc-service"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
  </div>
{/if}

<!-- XHTTP (SplitHTTP) settings -->
{#if network === 'xhttp'}
  <div class="pl-3 border-l-2 border-cyan-500/30 space-y-3">
    <p class="text-xs font-medium text-cyan-400">XHTTP (SplitHTTP)</p>
    <div>
      <label for="vless-xhp" class="block text-xs font-medium text-zinc-400 mb-1">Path</label>
      <input id="vless-xhp" type="text" bind:value={xhttpPath} placeholder="/xhttp"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
    <div>
      <label for="vless-xhh" class="block text-xs font-medium text-zinc-400 mb-1">Host</label>
      <input id="vless-xhh" type="text" bind:value={xhttpHost} placeholder="example.com"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
    <div>
      <label for="vless-xhm" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.mode')}</label>
      <select id="vless-xhm" bind:value={xhttpMode}
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
        <option value="auto">auto</option>
        <option value="packet-up">packet-up</option>
        <option value="stream-up">stream-up</option>
        <option value="stream-one">stream-one</option>
      </select>
    </div>
  </div>
{/if}

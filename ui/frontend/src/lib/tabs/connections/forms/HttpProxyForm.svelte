<script>
  import { t } from '../../../i18n';

  export let server = '';
  export let port = '8080';
  export let username = '';
  export let password = '';
  export let tls = false;
  export let tlsSkipVerify = false;
</script>

<div>
  <label for="http-server" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.server')}</label>
  <input id="http-server" type="text" bind:value={server} placeholder="proxy.corp.com"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div>
  <label for="http-port" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.port')}</label>
  <input id="http-port" type="text" bind:value={port} placeholder="8080"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="http-user" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.login')}</label>
    <input id="http-user" type="text" bind:value={username} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="http-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.password')}</label>
    <input id="http-pass" type="password" bind:value={password} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
  <input type="checkbox" bind:checked={tls} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
  TLS (HTTPS Proxy)
</label>
{#if tls}
  <label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer ml-5">
    <input type="checkbox" bind:checked={tlsSkipVerify} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
    {$t('connections.noVerifyCert')}
  </label>
{/if}
<div class="px-3 py-2 text-xs bg-yellow-900/20 border border-yellow-800/30 rounded-lg text-yellow-400">
  {$t('connections.httpNoUdp')}
</div>

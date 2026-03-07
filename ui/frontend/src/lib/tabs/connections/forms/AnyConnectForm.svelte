<script>
  import { t } from '../../../i18n';

  export let server = '';
  export let port = '443';
  export let username = '';
  export let password = '';
  export let group = '';
  export let tlsSkipVerify = false;
  export let userAgent = '';
</script>

<div>
  <label for="ac-server" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.server')}</label>
  <input id="ac-server" type="text" bind:value={server} placeholder="vpn.example.com"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="ac-port" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.port')}</label>
    <input id="ac-port" type="text" bind:value={port} placeholder="443"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="ac-group" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.group')}</label>
    <input id="ac-group" type="text" bind:value={group} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="ac-user" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.login')}</label>
    <input id="ac-user" type="text" bind:value={username} placeholder="username"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="ac-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.password')}</label>
    <input id="ac-pass" type="password" bind:value={password} placeholder="password"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
  <input type="checkbox" bind:checked={tlsSkipVerify} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
  {$t('connections.tlsSkipVerify')}
</label>
<div>
  <label for="ac-ua" class="block text-xs font-medium text-zinc-400 mb-1">User-Agent <span class="text-zinc-500">({$t('connections.loginOptional')})</span></label>
  <input id="ac-ua" type="text" bind:value={userAgent} placeholder="AnyConnect Windows 5.1.15.287"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none font-mono" />
</div>

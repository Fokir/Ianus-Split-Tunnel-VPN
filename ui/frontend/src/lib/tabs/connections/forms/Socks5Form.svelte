<script>
  import { t } from '../../../i18n';

  export let server = '';
  export let port = '1080';
  export let username = '';
  export let password = '';
  export let udpEnabled = true;
</script>

<div>
  <label for="s5-server" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.server')}</label>
  <input id="s5-server" type="text" bind:value={server} placeholder="proxy.example.com"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div>
  <label for="s5-port" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.port')}</label>
  <input id="s5-port" type="text" bind:value={port} placeholder="1080"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="s5-user" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.login')}</label>
    <input id="s5-user" type="text" bind:value={username} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="s5-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.password')}</label>
    <input id="s5-pass" type="password" bind:value={password} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
  <input type="checkbox" bind:checked={udpEnabled} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
  UDP ASSOCIATE
</label>

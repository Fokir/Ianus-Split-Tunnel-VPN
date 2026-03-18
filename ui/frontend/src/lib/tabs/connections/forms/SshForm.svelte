<script>
  import { t } from '../../../i18n';
  import * as api from '../../../api.js';

  export let server = '';
  export let port = '22';
  export let username = '';
  export let password = '';
  export let privateKeyPath = '';
  export let privateKeyPassphrase = '';
  export let hostKey = '';
  export let insecureSkipHostKey = false;
  export let keepaliveInterval = '30';

  async function browseKey() {
    try {
      const sshDir = await api.getSSHDir();
      const path = await api.pickFileInDir(
        $t('connections.sshPrivateKey'),
        'SSH Keys',
        '*',
        sshDir || ''
      );
      if (path) privateKeyPath = path;
    } catch (e) {
      // user cancelled
    }
  }
</script>

<div class="grid grid-cols-[1fr_auto] gap-3">
  <div>
    <label for="ssh-server" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.server')}</label>
    <input id="ssh-server" type="text" bind:value={server} placeholder="example.com"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="ssh-port" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.port')}</label>
    <input id="ssh-port" type="text" bind:value={port} placeholder="22"
      class="w-[80px] px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="ssh-user" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.login')}</label>
    <input id="ssh-user" type="text" bind:value={username} placeholder=""
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="ssh-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.password')}</label>
    <input id="ssh-pass" type="password" bind:value={password} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<div>
  <label for="ssh-key" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.sshPrivateKey')}</label>
  <div class="flex gap-2">
    <input id="ssh-key" type="text" bind:value={privateKeyPath} placeholder={$t('connections.sshPrivateKeyPlaceholder')}
      class="flex-1 px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    <button type="button" on:click={browseKey}
      class="px-3 py-2 text-sm rounded-lg bg-zinc-700 text-zinc-300 hover:bg-zinc-600 transition-colors whitespace-nowrap">
      {$t('connections.browse')}
    </button>
  </div>
</div>
{#if privateKeyPath}
  <div>
    <label for="ssh-key-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.sshKeyPassphrase')}</label>
    <input id="ssh-key-pass" type="password" bind:value={privateKeyPassphrase} placeholder={$t('connections.loginOptional')}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
{/if}
<div>
  <label for="ssh-keepalive" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.sshKeepalive')}</label>
  <input id="ssh-keepalive" type="text" bind:value={keepaliveInterval} placeholder="30"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<p class="text-xs text-amber-400/70">{$t('connections.sshNoUdp')}</p>

<script>
  import { t } from '../../../i18n';
  import { pickFile } from '../../../api';

  export let server = '';
  export let port = '443';
  export let username = '';
  export let password = '';
  export let group = '';
  export let tlsSkipVerify = false;
  export let userAgent = '';
  export let clientCertMode = '';
  export let clientCert = '';
  export let clientKey = '';
  export let clientCertPassword = '';
  export let proxyUrl = '';
  export let proxyUsername = '';
  export let proxyPassword = '';
  export let dtls = false;

  // Detect certificate file type for conditional UI.
  $: certExt = clientCert ? clientCert.split('.').pop().toLowerCase() : '';
  $: isPKCS12 = certExt === 'p12' || certExt === 'pfx';
  $: isCerOnly = certExt === 'cer' || certExt === 'crt' || certExt === 'der';
  $: needsKeyFile = !isPKCS12 && !isCerOnly; // PEM files may need a separate key

  async function browseCert() {
    const path = await pickFile(
      $t('connections.clientCertPath'),
      'Certificate',
      '*.pem;*.cer;*.crt;*.der;*.p12;*.pfx'
    );
    if (path) {
      clientCert = path;
      // Clear key/password when switching file types.
      const ext = path.split('.').pop().toLowerCase();
      if (ext === 'p12' || ext === 'pfx' || ext === 'cer' || ext === 'crt' || ext === 'der') {
        clientKey = '';
      }
      if (ext !== 'p12' && ext !== 'pfx') {
        clientCertPassword = '';
      }
    }
  }

  async function browseKey() {
    const path = await pickFile($t('connections.clientKeyPath'), 'PEM / KEY', '*.pem;*.key');
    if (path) clientKey = path;
  }
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
<div>
  <label for="ac-cert-mode" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.clientCert')} <span class="text-zinc-500">({$t('connections.loginOptional')})</span></label>
  <select id="ac-cert-mode" bind:value={clientCertMode}
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
    <option value="">{$t('connections.clientCertNone')}</option>
    <option value="auto">{$t('connections.clientCertAuto')}</option>
    <option value="file">{$t('connections.clientCertFile')}</option>
  </select>
</div>
<!-- Proxy settings -->
<div>
  <label for="ac-proxy" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.proxyUrl')} <span class="text-zinc-500">({$t('connections.loginOptional')})</span></label>
  <input id="ac-proxy" type="text" bind:value={proxyUrl} placeholder="http://proxy.example.com:8080"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none font-mono" />
</div>
{#if proxyUrl}
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label for="ac-proxy-user" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.proxyUsername')} <span class="text-zinc-500">({$t('connections.loginOptional')})</span></label>
      <input id="ac-proxy-user" type="text" bind:value={proxyUsername} placeholder="username"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
    <div>
      <label for="ac-proxy-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.proxyPassword')} <span class="text-zinc-500">({$t('connections.loginOptional')})</span></label>
      <input id="ac-proxy-pass" type="password" bind:value={proxyPassword} placeholder="password"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
  </div>
{/if}
<!-- DTLS toggle -->
<label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
  <input type="checkbox" bind:checked={dtls} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
  {$t('connections.dtlsEnable')}
</label>
{#if clientCertMode === 'file'}
  <div>
    <label for="ac-cert" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.clientCertPath')}</label>
    <div class="flex gap-1.5">
      <input id="ac-cert" type="text" bind:value={clientCert} placeholder="/path/to/cert.pem, .p12, .pfx, .cer"
        class="flex-1 min-w-0 px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none font-mono" />
      <button type="button" on:click={browseCert}
        class="px-2.5 py-2 text-sm bg-zinc-700 hover:bg-zinc-600 border border-zinc-600 rounded-lg text-zinc-300 transition-colors shrink-0"
        title="Browse">…</button>
    </div>
  </div>
  {#if isPKCS12}
    <!-- PKCS12: needs password, no separate key file -->
    <div>
      <label for="ac-cert-pw" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.clientCertPassword')} <span class="text-zinc-500">({$t('connections.clientCertPasswordHint')})</span></label>
      <input id="ac-cert-pw" type="password" bind:value={clientCertPassword} placeholder=""
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
    </div>
  {:else if isCerOnly}
    <!-- CER/CRT/DER: key is looked up in system store, no extra fields needed -->
    <p class="text-xs text-zinc-500">{$t('connections.clientCertAuto')} — {$t('connections.clientKeyHint')}</p>
  {:else if needsKeyFile}
    <!-- PEM: optionally needs separate key file -->
    <div>
      <label for="ac-key" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.clientKeyPath')} <span class="text-zinc-500">({$t('connections.clientKeyHint')})</span></label>
      <div class="flex gap-1.5">
        <input id="ac-key" type="text" bind:value={clientKey} placeholder="/path/to/client-key.pem"
          class="flex-1 min-w-0 px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none font-mono" />
        <button type="button" on:click={browseKey}
          class="px-2.5 py-2 text-sm bg-zinc-700 hover:bg-zinc-600 border border-zinc-600 rounded-lg text-zinc-300 transition-colors shrink-0"
          title="Browse">…</button>
      </div>
    </div>
  {/if}
{/if}

<script>
  import { t } from '../../../i18n';

  export let server = '';
  export let password = '';
  export let obfsType = '';
  export let obfsPassword = '';
  export let sni = '';
  export let insecure = false;
  export let upMbps = '';
  export let downMbps = '';
</script>

<div>
  <label for="hy2-server" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.server')}</label>
  <input id="hy2-server" type="text" bind:value={server} placeholder="example.com:443"
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div>
  <label for="hy2-password" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.password')}</label>
  <input id="hy2-password" type="password" bind:value={password} placeholder=""
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div>
  <label for="hy2-sni" class="block text-xs font-medium text-zinc-400 mb-1">SNI</label>
  <input id="hy2-sni" type="text" bind:value={sni} placeholder={$t('connections.hy2SniPlaceholder')}
    class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="hy2-obfs-type" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.hy2ObfsType')}</label>
    <select id="hy2-obfs-type" bind:value={obfsType}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none">
      <option value="">{$t('connections.hy2ObfsNone')}</option>
      <option value="salamander">Salamander</option>
    </select>
  </div>
  <div>
    <label for="hy2-obfs-pass" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.hy2ObfsPassword')}</label>
    <input id="hy2-obfs-pass" type="password" bind:value={obfsPassword} placeholder=""
      disabled={obfsType !== 'salamander'}
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none disabled:opacity-40" />
  </div>
</div>
<div class="grid grid-cols-2 gap-3">
  <div>
    <label for="hy2-up" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.hy2UpMbps')}</label>
    <input id="hy2-up" type="text" bind:value={upMbps} placeholder="0 (auto)"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
  <div>
    <label for="hy2-down" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.hy2DownMbps')}</label>
    <input id="hy2-down" type="text" bind:value={downMbps} placeholder="0 (auto)"
      class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 focus:border-blue-500 focus:outline-none" />
  </div>
</div>
<label class="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
  <input type="checkbox" bind:checked={insecure} class="rounded border-zinc-600 bg-zinc-800 text-blue-500 focus:ring-blue-500" />
  {$t('connections.noVerifyCert')}
</label>

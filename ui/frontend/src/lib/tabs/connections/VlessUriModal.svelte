<script>
  import { createEventDispatcher } from 'svelte';
  import * as api from '../../api.js';
  import ErrorAlert from '../../ErrorAlert.svelte';
  import { Modal } from '../../components';
  import { t } from '../../i18n';

  export let open = false;

  const dispatch = createEventDispatcher();

  let uriValue = '';
  let uriSaving = false;
  let uriError = '';

  $: if (open) {
    uriValue = '';
    uriSaving = false;
    uriError = '';
  }

  function close() {
    dispatch('close');
  }

  async function saveUri() {
    const uri = uriValue.trim();
    if (!uri) { uriError = $t('connections.vlessUriEmpty'); return; }
    if (!uri.startsWith('vless://')) { uriError = $t('connections.vlessUriInvalid'); return; }
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
      dispatch('added');
    } catch (err) {
      uriError = err.message;
    } finally {
      uriSaving = false;
    }
  }
</script>

<Modal {open} title={$t('connections.vlessImport')} width="max-w-lg" on:close={close}>
  <div class="space-y-3">
    {#if uriError}
      <ErrorAlert message={uriError} />
    {/if}
    <div>
      <label for="vless-uri" class="block text-xs font-medium text-zinc-400 mb-1">{$t('connections.vlessUriLabel')}</label>
      <textarea
        id="vless-uri"
        bind:value={uriValue}
        placeholder="vless://uuid@host:port?type=tcp&security=reality&..."
        rows="3"
        class="w-full px-3 py-2 text-sm bg-zinc-800 border border-zinc-700 rounded-lg text-zinc-200 font-mono focus:border-blue-500 focus:outline-none resize-none"
      ></textarea>
    </div>
    <p class="text-xs text-zinc-500">{$t('connections.vlessUriHint')}</p>
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
      disabled={uriSaving}
      on:click={saveUri}
    >
      {uriSaving ? $t('connections.importing') : $t('connections.import')}
    </button>
  </svelte:fragment>
</Modal>

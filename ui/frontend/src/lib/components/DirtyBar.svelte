<script>
  import { createEventDispatcher } from 'svelte';
  import { t } from '../i18n';

  export let dirty = false;
  export let saving = false;
  export let saveText = '';
  export let cancelText = '';
  export let savingText = '';

  const dispatch = createEventDispatcher();

  $: saveLabel = saveText || $t('common.save');
  $: cancelLabel = cancelText || $t('common.cancel');
  $: savingLabel = savingText || $t('common.saving');
</script>

{#if dirty}
  <div class="sticky top-0 z-10 flex justify-end gap-2 py-2 px-4 bg-zinc-900/95 backdrop-blur-sm border-b border-zinc-700/40">
    <button
      class="px-3 py-1.5 text-xs font-medium rounded-md bg-zinc-700/50 text-zinc-300 hover:bg-zinc-700 transition-colors"
      on:click={() => dispatch('cancel')}
      disabled={saving}
    >
      {cancelLabel}
    </button>
    <button
      class="px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors disabled:opacity-40"
      on:click={() => dispatch('save')}
      disabled={saving}
    >
      {saving ? savingLabel : saveLabel}
    </button>
  </div>
{/if}

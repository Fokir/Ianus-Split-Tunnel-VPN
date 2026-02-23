<script>
  export let message = '';
  export let className = '';

  let copied = false;

  async function copyError() {
    try {
      await navigator.clipboard.writeText(message);
      copied = true;
      setTimeout(() => copied = false, 1500);
    } catch {}
  }
</script>

<div class="flex items-start gap-2 {className || 'px-3 py-2 text-sm bg-red-900/30 border border-red-800/50 rounded-lg text-red-300'}">
  <span class="flex-1 min-w-0 break-words">{message}</span>
  <button
    on:click={copyError}
    class="flex-none p-0.5 rounded hover:bg-white/10 transition-colors text-current opacity-40 hover:opacity-100"
    title="Копировать"
  >
    {#if copied}
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-3.5 h-3.5">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
    {:else}
      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="w-3.5 h-3.5">
        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
      </svg>
    {/if}
  </button>
</div>

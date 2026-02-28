<script>
  /** Size classes: 'sm' = h-3 w-3, 'md' = h-5 w-5 */
  export let size = 'md';
  /** Optional text to show next to the spinner */
  export let text = '';

  $: sizeClass = size === 'sm' ? 'h-3 w-3' : 'h-5 w-5';
</script>

<div class="flex items-center justify-center text-zinc-500">
  <svg class="animate-spin {sizeClass} {text ? 'mr-2' : ''}" viewBox="0 0 24 24" fill="none">
    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
  </svg>
  {#if text}<span>{text}</span>{/if}
</div>

<script>
  /** @type {string} Two-letter country code */
  export let code = '';
  /** @type {string} Domain name (for CDN/service provider detection) */
  export let domain = '';
  /** @type {number} Icon width in pixels */
  export let size = 16;
  /** @type {boolean} Show text code next to icon */
  export let showCode = false;

  const CDN_PATTERNS = [
    { pattern: 'cloudflare', label: 'CF', bg: 'bg-orange-500/20', text: 'text-orange-400' },
    { pattern: 'google',     label: 'G',  bg: 'bg-blue-500/20',   text: 'text-blue-400' },
    { pattern: 'youtube',    label: 'YT', bg: 'bg-red-500/20',    text: 'text-red-400' },
    { pattern: 'amazonaws',  label: 'AWS', bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
    { pattern: 'microsoft',  label: 'MS', bg: 'bg-cyan-500/20',   text: 'text-cyan-400' },
    { pattern: 'azure',      label: 'AZ', bg: 'bg-cyan-500/20',   text: 'text-cyan-400' },
    { pattern: 'akamai',     label: 'AK', bg: 'bg-indigo-500/20', text: 'text-indigo-400' },
    { pattern: 'fastly',     label: 'FY', bg: 'bg-pink-500/20',   text: 'text-pink-400' },
    { pattern: 'facebook',   label: 'FB', bg: 'bg-blue-600/20',   text: 'text-blue-500' },
    { pattern: 'meta',       label: 'M',  bg: 'bg-blue-600/20',   text: 'text-blue-500' },
    { pattern: 'apple',      label: 'A',  bg: 'bg-zinc-500/20',   text: 'text-zinc-300' },
    { pattern: 'icloud',     label: 'iC', bg: 'bg-zinc-500/20',   text: 'text-zinc-300' },
  ];

  $: domainLower = (domain || '').toLowerCase();
  $: normalizedCode = (code || '').toLowerCase().trim();

  $: cdnMatch = (() => {
    if (!domainLower) return null;
    for (const entry of CDN_PATTERNS) {
      if (domainLower.includes(entry.pattern)) return entry;
    }
    return null;
  })();

  $: isCountry = normalizedCode.length === 2 && /^[a-z]{2}$/.test(normalizedCode);

  $: flagSrc = isCountry ? `/flags/${normalizedCode}.svg` : '';
  $: height = Math.round(size * 0.75);

  let imgError = false;
  $: if (normalizedCode) imgError = false;
</script>

{#if cdnMatch}
  <span class="inline-flex items-center justify-center rounded text-[0.6rem] font-bold leading-none {cdnMatch.bg} {cdnMatch.text}"
    style="width:{size}px;height:{height}px" title={domain}>
    {cdnMatch.label}
  </span>
  {#if showCode && isCountry}
    <img src={flagSrc} alt={normalizedCode.toUpperCase()} width={Math.round(size * 0.75)} height={Math.round(height * 0.75)}
      class="inline-block rounded-sm" on:error={() => {}} />
  {/if}
{:else if isCountry && !imgError}
  <img src={flagSrc} alt={normalizedCode.toUpperCase()} width={size} height={height}
    class="inline-block rounded-sm" style="min-width:{size}px"
    on:error={() => imgError = true}
  />
  {#if showCode}<span class="text-[0.6rem] uppercase text-zinc-500">{normalizedCode}</span>{/if}
{:else if code}
  <span class="text-[0.6rem] uppercase text-zinc-500">{code}</span>
{:else}
  <span class="text-zinc-600">—</span>
{/if}

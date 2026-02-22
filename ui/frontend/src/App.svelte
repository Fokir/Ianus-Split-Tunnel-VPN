<script>
  import { onMount, onDestroy } from 'svelte';
  import { Events } from '@wailsio/runtime';
  import ConnectionsTab from './lib/tabs/ConnectionsTab.svelte';
  import SubscriptionsTab from './lib/tabs/SubscriptionsTab.svelte';
  import RulesTab from './lib/tabs/RulesTab.svelte';
  import DomainsTab from './lib/tabs/DomainsTab.svelte';
  import SettingsTab from './lib/tabs/SettingsTab.svelte';
  import LogsTab from './lib/tabs/LogsTab.svelte';
  import AboutTab from './lib/tabs/AboutTab.svelte';
  import StatusBar from './lib/StatusBar.svelte';
  import TitleBar from './lib/TitleBar.svelte';

  const tabs = [
    { id: 'connections',    label: 'Подключения', icon: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z' },
    { id: 'subscriptions', label: 'Подписки',    icon: 'M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z' },
    { id: 'rules',          label: 'Правила',     icon: 'M3 13h2v-2H3v2zm0 4h2v-2H3v2zm0-8h2V7H3v2zm4 4h14v-2H7v2zm0 4h14v-2H7v2zM7 7v2h14V7H7z' },
    { id: 'domains',     label: 'Домены',      icon: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z' },
    { id: 'settings',    label: 'Настройки',   icon: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 00-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1115.6 12 3.6 3.6 0 0112 15.6z' },
    { id: 'logs',        label: 'Логи',        icon: 'M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-7 9h-2V5h2v6zm0 4h-2v-2h2v2z' },
    { id: 'about',       label: 'О программе', icon: 'M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z' },
  ];

  let activeTab = 'connections';

  function handleNavigate(event) {
    const path = event.data;
    if (path === '/settings') activeTab = 'settings';
    else if (path === '/subscriptions') activeTab = 'subscriptions';
    else if (path === '/rules') activeTab = 'rules';
    else if (path === '/domains') activeTab = 'domains';
    else if (path === '/logs') activeTab = 'logs';
    else if (path === '/about') activeTab = 'about';
    else activeTab = 'connections';
  }

  onMount(() => {
    Events.On('navigate', handleNavigate);
  });

  onDestroy(() => {
    Events.Off('navigate', handleNavigate);
  });
</script>

<div class="flex flex-col h-screen bg-zinc-900 text-zinc-100 select-none">
  <!-- Custom titlebar -->
  <TitleBar />

  <!-- Tab bar -->
  <nav class="flex border-b border-zinc-700/60 bg-zinc-900/80 backdrop-blur-sm shrink-0">
    {#each tabs as tab}
      <button
        class="relative flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors
               {activeTab === tab.id
                 ? 'text-blue-400'
                 : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'}"
        on:click={() => activeTab = tab.id}
      >
        <svg class="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="currentColor">
          <path d={tab.icon}/>
        </svg>
        {tab.label}
        {#if activeTab === tab.id}
          <span class="absolute bottom-0 left-2 right-2 h-0.5 bg-blue-400 rounded-full"></span>
        {/if}
      </button>
    {/each}
  </nav>

  <!-- Tab content -->
  <main class="flex-1 overflow-y-auto">
    {#if activeTab === 'connections'}
      <ConnectionsTab />
    {:else if activeTab === 'subscriptions'}
      <SubscriptionsTab />
    {:else if activeTab === 'rules'}
      <RulesTab />
    {:else if activeTab === 'domains'}
      <DomainsTab />
    {:else if activeTab === 'settings'}
      <SettingsTab />
    {:else if activeTab === 'logs'}
      <LogsTab />
    {:else if activeTab === 'about'}
      <AboutTab />
    {/if}
  </main>

  <!-- Status bar -->
  <StatusBar />
</div>

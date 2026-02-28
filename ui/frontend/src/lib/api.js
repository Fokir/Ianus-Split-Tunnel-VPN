/**
 * API wrapper around Wails-generated bindings.
 * Wails v3 generates JS bindings from Go BindingService methods.
 */
import { BindingService } from '../../bindings/awg-split-tunnel/ui';

// ─── Service status ─────────────────────────────────────────────────

export function getStatus() {
  return BindingService.GetStatus();
}

// ─── Tunnels ────────────────────────────────────────────────────────

export function listTunnels() {
  return BindingService.ListTunnels();
}

export function connectTunnel(tunnelID) {
  return BindingService.ConnectTunnel(tunnelID);
}

export function disconnectTunnel(tunnelID) {
  return BindingService.DisconnectTunnel(tunnelID);
}

export function restartTunnel(tunnelID) {
  return BindingService.RestartTunnel(tunnelID);
}

export function connectAll() {
  return BindingService.ConnectAll();
}

export function disconnectAll() {
  return BindingService.DisconnectAll();
}

export function addTunnel(params) {
  return BindingService.AddTunnel(params);
}

export function removeTunnel(tunnelID) {
  return BindingService.RemoveTunnel(tunnelID);
}

export function saveTunnelOrder(tunnelIds) {
  return BindingService.SaveTunnelOrder(tunnelIds);
}

export function renameTunnel(tunnelID, name) {
  return BindingService.RenameTunnel(tunnelID, name);
}

// ─── Rules ──────────────────────────────────────────────────────────

export function listRules() {
  return BindingService.ListRules();
}

export function saveRules(rules) {
  return BindingService.SaveRules(rules);
}

// ─── Domain rules ───────────────────────────────────────────────────

export function listDomainRules() {
  return BindingService.ListDomainRules();
}

export function saveDomainRules(rules) {
  return BindingService.SaveDomainRules(rules);
}

export function listGeositeCategories() {
  return BindingService.ListGeositeCategories();
}

export function listGeoIPCategories() {
  return BindingService.ListGeoIPCategories();
}

export function updateGeosite() {
  return BindingService.UpdateGeosite();
}

// ─── Notifications ──────────────────────────────────────────────────

export function setNotificationPreferences(enabled, tunnelErrors, updates) {
  return BindingService.SetNotificationPreferences(enabled, tunnelErrors, updates);
}

// ─── Platform ──────────────────────────────────────────────────────

export function getPlatform() {
  return BindingService.GetPlatform();
}

// ─── Processes ──────────────────────────────────────────────────────

export function listProcesses(nameFilter = '') {
  return BindingService.ListProcesses(nameFilter);
}

// ─── DNS ────────────────────────────────────────────────────────────

export function flushDNS() {
  return BindingService.FlushDNS();
}

// ─── Config ─────────────────────────────────────────────────────────

export function getConfig() {
  return BindingService.GetConfig();
}

export function saveConfig(config, restartIfConnected) {
  return BindingService.SaveConfig(config, restartIfConnected);
}

// ─── Autostart ──────────────────────────────────────────────────────

export function getAutostart() {
  return BindingService.GetAutostart();
}

export function setAutostart(enabled, restoreConnections) {
  return BindingService.SetAutostart(enabled, restoreConnections);
}

// ─── Subscriptions ───────────────────────────────────────────────

export function listSubscriptions() {
  return BindingService.ListSubscriptions();
}

export function addSubscription(params) {
  return BindingService.AddSubscription(params);
}

export function removeSubscription(name) {
  return BindingService.RemoveSubscription(name);
}

export function refreshSubscription(name) {
  return BindingService.RefreshSubscription(name);
}

export function refreshAllSubscriptions() {
  return BindingService.RefreshAllSubscriptions();
}

export function updateSubscription(params) {
  return BindingService.UpdateSubscription(params);
}

// ─── Stats streaming ──────────────────────────────────────────────

export function startStatsStream() {
  return BindingService.StartStatsStream();
}

// ─── Updates ──────────────────────────────────────────────────────

export function checkUpdate() {
  return BindingService.CheckUpdate();
}

export function applyUpdate() {
  return BindingService.ApplyUpdate();
}

export function startUpdateNotifier() {
  return BindingService.StartUpdateNotifier();
}

// ─── Conflicting services ────────────────────────────────────────

export function checkConflictingServices() {
  return BindingService.CheckConflictingServices();
}

export function stopConflictingServices(names) {
  return BindingService.StopConflictingServices(names);
}

// ─── DPI Bypass ──────────────────────────────────────────────────

export function getDPIConfig() {
  return BindingService.GetDPIConfig();
}

export function setDPIEnabled(enabled) {
  return BindingService.SetDPIEnabled(enabled);
}

export function listDPIStrategies() {
  return BindingService.ListDPIStrategies();
}

export function fetchDPIStrategies() {
  return BindingService.FetchDPIStrategies();
}

export function selectDPIStrategy(name) {
  return BindingService.SelectDPIStrategy(name);
}

export function startDPISearch(baseStrategy) {
  return BindingService.StartDPISearch(baseStrategy);
}

export function stopDPISearch() {
  return BindingService.StopDPISearch();
}

export function probeDPI(domain, strategyName) {
  return BindingService.ProbeDPI(domain, strategyName);
}

export function startDPISearchStream() {
  return BindingService.StartDPISearchStream();
}

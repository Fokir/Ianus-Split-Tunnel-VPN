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

// ─── Rules ──────────────────────────────────────────────────────────

export function listRules() {
  return BindingService.ListRules();
}

export function saveRules(rules) {
  return BindingService.SaveRules(rules);
}

// ─── Processes ──────────────────────────────────────────────────────

export function listProcesses(nameFilter = '') {
  return BindingService.ListProcesses(nameFilter);
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

export function setAutostart(enabled) {
  return BindingService.SetAutostart(enabled);
}

import React from 'react';
import { Database, ShieldAlert, ShieldCheck, HelpCircle, HardDrive, RefreshCw, Key } from 'lucide-react';

export const ThreatIntelCard = ({ threatIntel }) => {
  if (!threatIntel) return null;

  const isAvailable = threatIntel.available;
  const isCached = threatIntel.cached;
  const maliciousCount = threatIntel.malicious || 0;
  const suspiciousCount = threatIntel.suspicious || 0;
  const harmlessCount = threatIntel.harmless || 0;
  const undetectedCount = threatIntel.undetected || 0;
  const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;

  return (
    <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide flex items-center space-x-2">
              <span>Threat Intelligence Feed</span>
              <span className="text-[10px] font-normal px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                {threatIntel.source || 'VirusTotal v3'}
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Multi-Vendor Security Vendor Consensus & Global Reputation
            </p>
          </div>
        </div>

        <div>
          {isAvailable ? (
            <div className="flex items-center space-x-2">
              {isCached ? (
                <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-mono bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
                  <HardDrive className="w-3.5 h-3.5" />
                  <span>Cache Hit (24h TTL)</span>
                </span>
              ) : (
                <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-mono bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Live Vendor Query</span>
                </span>
              )}
            </div>
          ) : (
            <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-mono bg-slate-800 border border-slate-700 text-slate-400">
              <Key className="w-3.5 h-3.5" />
              <span>Unconfigured / Offline</span>
            </span>
          )}
        </div>
      </div>

      {isAvailable ? (
        <div className="space-y-6">
          {/* Vendor Detection Metric Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/90 border border-red-500/30">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-red-300">Malicious</span>
                <ShieldAlert className="w-4 h-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-red-400">{maliciousCount}</div>
              <span className="text-[10px] font-mono text-slate-500">Security Vendors</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-500/30">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-amber-300">Suspicious</span>
                <HelpCircle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-amber-400">{suspiciousCount}</div>
              <span className="text-[10px] font-mono text-slate-500">Security Vendors</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-emerald-500/30">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-emerald-300">Harmless</span>
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-400">{harmlessCount}</div>
              <span className="text-[10px] font-mono text-slate-500">Security Vendors</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-slate-400">Undetected</span>
                <HelpCircle className="w-4 h-4 text-slate-500" />
              </div>
              <div className="text-2xl font-bold font-mono text-slate-300">{undetectedCount}</div>
              <span className="text-[10px] font-mono text-slate-500">
                {totalEngines > 0 ? `of ${totalEngines} total` : 'No signals'}
              </span>
            </div>
          </div>

          {/* Threat Intel Risk Score summary */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
            <div>
              <span className="text-slate-400">Normalized Threat Intelligence Score:</span>
              <div className="text-slate-200 font-bold text-sm mt-0.5">
                {threatIntel.score !== null && threatIntel.score !== undefined
  ? threatIntel.score
  : 'N/A'} / 100
              </div>
            </div>
            <div className="text-slate-400 text-right sm:text-right">
              <span>Reputation Consensus Score:</span>
              <div className="text-cyan-300 font-bold text-sm mt-0.5">
                {threatIntel.reputation ?? 0}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 text-xs font-mono text-slate-400 space-y-2">
          <p>
            VirusTotal API integration is inactive ({threatIntel.error || 'No API key configured in backend environment'}).
          </p>
          <p className="text-slate-500">
            ThreatLens safely skips this engine and mathematically re-weights heuristic & ML scores to maintain 100% detection coverage.
          </p>
        </div>
      )}
    </div>
  );
};

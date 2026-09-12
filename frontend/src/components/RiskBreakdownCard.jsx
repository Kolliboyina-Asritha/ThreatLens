import React from 'react';
import { Cpu, ShieldCheck, Database, Sliders, AlertCircle, CheckCircle2, XCircle } from 'lucide-react';

export const RiskBreakdownCard = ({ breakdown, fusedScore }) => {
  if (!breakdown) return null;

  const engines = [
    {
      key: 'heuristics',
      name: 'Heuristic Rule Engine',
      desc: '9 structural pattern & syntax inspection rules',
      icon: ShieldCheck,
      color: 'text-cyan-400',
      barColor: 'bg-cyan-500',
      data: breakdown.heuristics
    },
    {
      key: 'machineLearning',
      name: 'Random Forest ML Engine',
      desc: '18-feature lexical classifier trained on Tranco & PhishTank',
      icon: Cpu,
      color: 'text-indigo-400',
      barColor: 'bg-indigo-500',
      data: breakdown.machineLearning || breakdown.ml
    },
    {
      key: 'threatIntelligence',
      name: 'VirusTotal Threat Intel',
      desc: 'Multi-vendor reputation & threat signature ledger',
      icon: Database,
      color: 'text-emerald-400',
      barColor: 'bg-emerald-500',
      data: breakdown.threatIntelligence
    }
  ];

  const activeEnginesList = Array.isArray(breakdown.activeEngines)
    ? breakdown.activeEngines
    : Object.keys(breakdown).filter((k) => breakdown[k]?.available);

  const activeCount = activeEnginesList.length;
  const isRenormalized = activeCount > 0 && activeCount < 3;

  const displayFusedScore = typeof fusedScore === 'number'
    ? fusedScore
    : (typeof breakdown.totalFusedScore === 'number'
        ? breakdown.totalFusedScore
        : Math.round(
            (breakdown.heuristics?.contribution || 0) +
            (breakdown.machineLearning?.contribution || breakdown.ml?.contribution || 0) +
            (breakdown.threatIntelligence?.contribution || 0)
          ));

  return (
    <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <Sliders className="w-5 h-5 text-cyan-400" />
          <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide">
            Multi-Engine Risk Fusion Breakdown
          </h3>
        </div>
        <div className="flex items-center space-x-2">
          {isRenormalized && (
            <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-amber-500/10 border border-amber-500/30 text-amber-300">
              Weights Dynamically Renormalized ({activeCount}/3 Active)
            </span>
          )}
          <span className="text-xs font-mono text-slate-400">
            Fused Score: <span className="font-bold text-slate-100">{displayFusedScore}/100</span>
          </span>
        </div>
      </div>

      {isRenormalized && (
        <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-xs text-amber-200/90 font-mono flex items-start space-x-2">
          <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <span>
            One or more intelligence engines are currently offline or unconfigured. Active engine weights have been dynamically scaled so total fusion weight is 100%.
          </span>
        </div>
      )}

      {/* Engine Contribution Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {engines.map(({ key, name, desc, icon: Icon, color, barColor, data }) => {
          const isAvailable = Boolean(data?.available);
          const score = typeof data?.score === 'number' ? data.score : (isAvailable ? 0 : null);
          const weight = typeof data?.normalizedWeight === 'number'
            ? data.normalizedWeight
            : (typeof data?.weight === 'number' ? data.weight : (typeof data?.baseWeight === 'number' ? data.baseWeight : 0));
          const contribution = typeof data?.contribution === 'number' ? data.contribution : 0;

          return (
            <div
              key={key}
              className={`p-4 rounded-xl border transition-all ${
                isAvailable
                  ? 'bg-slate-900/80 border-slate-700/80 hover:border-slate-600'
                  : 'bg-slate-950/40 border-slate-800/60 opacity-70'
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <Icon className={`w-4 h-4 ${color}`} />
                  <span className="font-mono text-xs font-bold text-slate-200">{name}</span>
                </div>
                {isAvailable ? (
                  <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>Active</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                    <XCircle className="w-3 h-3" />
                    <span>Offline / Unconfigured</span>
                  </span>
                )}
              </div>

              <p className="text-[11px] text-slate-400 mb-3 line-clamp-2">{desc}</p>

              {isAvailable ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-slate-400">Raw Score:</span>
                    <span className="font-bold text-slate-200">{score !== null ? `${score}/100` : '—'}</span>
                  </div>

                  {/* Progress bar */}
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${barColor} transition-all duration-500`}
                      style={{ width: `${Math.min(score || 0, 100)}%` }}
                    />
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-800">
                    <span>Applied Weight:</span>
                    <span className="text-slate-300 font-semibold">{(weight * 100).toFixed(1)}%</span>
                  </div>

                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span>Contribution:</span>
                    <span className="text-cyan-300 font-bold">+{contribution.toFixed(2)} pts</span>
                  </div>
                </div>
              ) : (
                <div className="py-3 text-center space-y-1">
                  <span className="text-xs font-mono text-slate-500 italic block">
                    {data?.error || data?.reason || 'Engine unconfigured / offline'}
                  </span>
                  <span className="text-[10px] font-mono text-slate-600 block">
                    Weight reallocated: 0.0%
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

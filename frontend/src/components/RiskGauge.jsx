import React from 'react';
import { getRiskColors } from '../utils/formatters.js';

export const RiskGauge = ({ score = 0, riskLevel = 'SAFE', title = 'Unified Risk Score' }) => {
  const colors = getRiskColors(riskLevel);
  const boundedScore = Math.max(0, Math.min(100, Math.round(score)));

  return (
    <div className={`flex flex-col items-center justify-center p-6 rounded-xl border bg-cyber-card ${colors.border} ${colors.glow} transition-all duration-300`}>
      <div className="text-xs uppercase tracking-widest text-slate-400 font-mono mb-2">
        {title}
      </div>

      <div className="relative flex items-baseline justify-center mb-3">
        <span className={`text-6xl font-extrabold font-mono tracking-tight ${colors.text}`}>
          {boundedScore}
        </span>
        <span className="text-2xl font-mono text-slate-500 ml-1">/100</span>
      </div>

      {/* Progress meter bar */}
      <div className="w-full bg-slate-800/80 rounded-full h-3 mb-4 overflow-hidden border border-slate-700/50">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-out ${colors.progress}`}
          style={{ width: `${boundedScore}%` }}
        />
      </div>

      {/* Risk Category Label */}
      <div className="flex items-center space-x-2">
        <span className="text-xs text-slate-400">Classification:</span>
        <span className={`font-mono font-bold text-sm uppercase tracking-wider ${colors.text}`}>
          {riskLevel.replace('_', ' ')}
        </span>
      </div>
    </div>
  );
};

import React from 'react';
import { AlertTriangle, CheckCircle } from 'lucide-react';
import { getSeverityStyle } from '../utils/formatters.js';
import { DualTierExplainer } from './DualTierExplainer.jsx';

export const IndicatorList = ({ indicators = [] }) => {
  if (!indicators || indicators.length === 0) {
    return (
      <div className="flex items-center space-x-3 p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300">
        <CheckCircle className="w-5 h-5 shrink-0" />
        <div>
          <p className="text-sm font-semibold">No Threat Indicators Detected</p>
          <p className="text-xs text-emerald-400/80">URL features conform to standard legitimate domain patterns.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {indicators.map((ind, idx) => (
        <div
          key={idx}
          className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-lg bg-cyber-card border border-cyber-border hover:border-slate-700 transition-colors gap-3"
        >
          <div className="flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold text-slate-200">
                  {ind.type.replace(/_/g, ' ')}
                </span>
                <span
                  className={`text-[10px] uppercase font-mono px-2 py-0.5 rounded border ${getSeverityStyle(
                    ind.severity
                  )}`}
                >
                  {ind.severity}
                </span>
                <DualTierExplainer
                  conceptKey={ind.type}
                  fallbackTitle={ind.type.replace(/_/g, ' ')}
                  buttonLabel="Explain"
                />
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">{ind.message}</p>
              
              {ind.details?.keywords && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {ind.details.keywords.map((kw, kidx) => (
                    <span
                      key={kidx}
                      className="px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300 rounded font-mono text-[11px]"
                    >
                      {kw}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center sm:flex-col sm:items-end font-mono text-xs text-slate-400 shrink-0">
            <span>Score Impact:</span>
            <span className="font-bold text-amber-400 sm:text-sm sm:mt-0.5">+{ind.score}</span>
          </div>
        </div>
      ))}
    </div>
  );
};

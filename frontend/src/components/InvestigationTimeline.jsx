import React from 'react';
import { History, CheckCircle2, AlertCircle, HardDrive, Clock, ArrowDown } from 'lucide-react';

const STAGE_LABELS = {
  URL_VALIDATION: 'URL Normalization & Validation',
  FEATURE_EXTRACTION: 'Structural Feature Extraction',
  HEURISTIC_ANALYSIS: 'Heuristic Rule Evaluation',
  ML_INFERENCE: 'Random Forest Inference',
  THREAT_INTEL_LOOKUP: 'Threat Intelligence Lookup',
  RISK_FUSION: 'Multi-Engine Risk Fusion',
  AI_EXPLANATION: 'AI Contextual Synthesis'
};

export const InvestigationTimeline = ({ timeline }) => {
  if (!timeline || !Array.isArray(timeline) || timeline.length === 0) return null;

  const totalDuration = timeline.reduce((sum, item) => sum + (item.durationMs || 0), 0);

  return (
    <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <History className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide">
              Investigation Execution Pipeline
            </h3>
            <p className="text-xs text-slate-400">
              7-Stage End-to-End Forensic Trace
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>Total Pipeline Latency: <span className="text-cyan-300 font-bold">{totalDuration}ms</span></span>
        </div>
      </div>

      {/* Horizontal / Vertical Timeline Flow */}
      <div className="space-y-3">
        {timeline.map((step, idx) => {
          const isLast = idx === timeline.length - 1;
          const status = step.status || 'COMPLETED';
          const isDegraded = status === 'DEGRADED';
          const isCached = status === 'CACHED';

          let statusBadge = (
            <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              <CheckCircle2 className="w-3 h-3" />
              <span>Completed</span>
            </span>
          );

          if (isDegraded) {
            statusBadge = (
              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/10 text-amber-400 border border-amber-500/30">
                <AlertCircle className="w-3 h-3" />
                <span>Degraded</span>
              </span>
            );
          } else if (isCached) {
            statusBadge = (
              <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                <HardDrive className="w-3 h-3" />
                <span>Cached</span>
              </span>
            );
          }

          return (
            <div key={idx} className="flex items-start space-x-3 group">
              {/* Step number and connection line */}
              <div className="flex flex-col items-center">
                <div
                  className={`w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-mono font-bold shrink-0 ${
                    isDegraded
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                  }`}
                >
                  {idx + 1}
                </div>
                {!isLast && <div className="w-px h-6 bg-slate-800 my-1 group-hover:bg-slate-700 transition-colors" />}
              </div>

              {/* Step info */}
              <div className="flex-1 p-3 rounded-lg bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                  <span className="font-mono text-xs font-bold text-slate-200">
                    {STAGE_LABELS[step.stage] || step.stage}
                  </span>
                  <div className="flex items-center space-x-2">
                    {statusBadge}
                    <span className="font-mono text-[10px] text-slate-500">
                      {step.durationMs ?? 0}ms
                    </span>
                  </div>
                </div>
                {step.details && (
                  <p className="text-[11px] font-mono text-slate-400 truncate">
                    {typeof step.details === 'object' ? JSON.stringify(step.details) : step.details}
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

import React from 'react';
import { Sparkles, AlertTriangle, ShieldCheck, Info, CheckCircle2, ShieldAlert } from 'lucide-react';

export const AIExplanationCard = ({ aiExplanation, riskLevel }) => {
  if (!aiExplanation) return null;

  const summary = aiExplanation.summary || 'No summary available.';
  const whyRisky = aiExplanation.whyRisky || [];
  const recommendations = aiExplanation.recommendations || [];
  const provider = aiExplanation.provider || 'ThreatLens Explanation Engine';
  const isLLM = provider.toLowerCase().includes('gemini');

  return (
    <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 text-cyan-300">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide flex items-center space-x-2">
              <span>AI Security Explanation & Triage</span>
            </h3>
            <p className="text-xs text-slate-400">
              Generative contextual synthesis and incident analyst briefing
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="px-2.5 py-1 rounded-full text-xs font-mono bg-purple-500/10 border border-purple-500/30 text-purple-300 flex items-center space-x-1.5">
            <Sparkles className="w-3 h-3 text-purple-400" />
            <span>{provider}</span>
          </span>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
        <div className="text-[11px] font-mono uppercase tracking-wider text-cyan-400 flex items-center space-x-1.5">
          <Info className="w-3.5 h-3.5" />
          <span>Executive Summary</span>
        </div>
        <p className="text-sm text-slate-200 leading-relaxed font-sans">
          {summary}
        </p>
      </div>

      {/* Two Column Grid: Why Risky vs Recommendations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Why is this risky? */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-3">
          <div className="flex items-center space-x-2 text-xs font-mono font-bold text-amber-300">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Key Threat Observations & Risk Drivers</span>
          </div>

          {whyRisky.length > 0 ? (
            <ul className="space-y-2 text-xs text-slate-300">
              {whyRisky.map((reason, idx) => (
                <li key={idx} className="flex items-start space-x-2">
                  <span className="text-amber-400/80 mt-0.5">•</span>
                  <span className="leading-normal">{reason}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">No significant threat risk factors identified.</p>
          )}
        </div>

        {/* Actionable Recommendations */}
        <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-3">
          <div className="flex items-center space-x-2 text-xs font-mono font-bold text-emerald-300">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Actionable Security Recommendations</span>
          </div>

          {recommendations.length > 0 ? (
            <ul className="space-y-2 text-xs text-slate-300">
              {recommendations.map((rec, idx) => (
                <li key={idx} className="flex items-start space-x-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span className="leading-normal">{rec}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">Standard web browsing precautions apply.</p>
          )}
        </div>
      </div>

      {/* Confidence & Explainability Disclaimer */}
      <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[11px] font-mono text-slate-500">
        <span className="flex items-center space-x-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-slate-500" />
          <span>Security Notice: AI synthesizes deterministic features & threat intel. Scores are computed by the deterministic fusion engine.</span>
        </span>
      </div>
    </div>
  );
};

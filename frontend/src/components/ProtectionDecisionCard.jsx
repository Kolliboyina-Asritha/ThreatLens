import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, XCircle, Sliders, ArrowLeft, ExternalLink, BookmarkPlus } from 'lucide-react';
import { protectionService } from '../services/protectionService.js';
import { DualTierExplainer } from './DualTierExplainer.jsx';

export const ProtectionDecisionCard = ({
  url,
  riskScore = 0,
  riskLevel = 'SAFE',
  recommendation = 'ALLOW',
  action = 'ALLOW',
  policyMode = 'ASK_ME',
  userDecision = null,
  overrideMatch = false,
  reasons = [],
  allowlistMatch = false,
  blocklistMatch = false,
  onDecisionChange
}) => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [isLocalOverridden, setIsLocalOverridden] = useState(false);

  const isOverridden = isLocalOverridden || userDecision === 'OVERRIDE' || overrideMatch;
  const isBlock = action === 'BLOCK' || recommendation === 'BLOCK';
  const isWarn = action === 'WARN' || recommendation === 'WARN';

  const handleAddAllowlist = async () => {
    setIsSubmitting(true);
    setStatusMsg('');
    try {
      await protectionService.addAllowlistEntry(url, 'URL');
      setStatusMsg('Added to your trusted Allowlist.');
      if (onDecisionChange) onDecisionChange();
    } catch (err) {
      setStatusMsg(err.response?.data?.message || 'Failed to add to allowlist.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddBlocklist = async () => {
    setIsSubmitting(true);
    setStatusMsg('');
    try {
      await protectionService.addBlocklistEntry(url, 'URL');
      setStatusMsg('Added to your personal Blocklist.');
      if (onDecisionChange) onDecisionChange();
    } catch (err) {
      setStatusMsg(err.response?.data?.message || 'Failed to add to blocklist.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOverride = async () => {
    setIsSubmitting(true);
    try {
      await protectionService.recordOverride(url, 'User chose to bypass warning on web dashboard.');
      setIsLocalOverridden(true);
      setStatusMsg('User override recorded. Access permitted.');
      if (onDecisionChange) onDecisionChange();
    } catch (err) {
      setStatusMsg(err.response?.data?.message || 'Failed to record override.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRemoveOverride = async () => {
    setIsSubmitting(true);
    try {
      await protectionService.removeOverride(encodeURIComponent(url));
      setIsLocalOverridden(false);
      setStatusMsg('User override cleared. Policy restored.');
      if (onDecisionChange) onDecisionChange();
    } catch (err) {
      setStatusMsg(err.response?.data?.message || 'Failed to clear override.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono font-bold text-slate-100 text-sm tracking-wide flex items-center space-x-2">
              <span>Protection & Enforcement Layer</span>
              <span className="text-[10px] font-normal px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">
                Mode: {policyMode}
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              User-controlled enforcement separated from threat analysis
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <DualTierExplainer
            conceptKey={`${policyMode}_MODE`}
            fallbackTitle={`${policyMode} Protection Mode`}
            buttonLabel="Explain Policy"
          />
        </div>
      </div>

      {/* Two Column Grid: Analysis Recommendation vs Actual Enforcement Action */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Recommendation Box */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
            ThreatLens Recommendation
          </span>
          <div className="flex items-center space-x-2">
            {recommendation === 'BLOCK' && (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-red-500/10 border border-red-500/40 text-red-400">
                <XCircle className="w-4 h-4" />
                <span>RECOMMENDS: BLOCK</span>
              </span>
            )}
            {recommendation === 'WARN' && (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/10 border border-amber-500/40 text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                <span>RECOMMENDS: WARN</span>
              </span>
            )}
            {recommendation === 'ALLOW' && (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/10 border border-emerald-500/40 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>RECOMMENDS: ALLOW</span>
              </span>
            )}
            <span className="text-xs font-mono text-slate-400">
              (Score: <strong className="text-slate-200">{riskScore}/100</strong>)
            </span>
          </div>
          <p className="text-xs text-slate-400 font-sans pt-1">
            Deterministic security evaluation derived from Heuristics, ML, and Threat Intelligence.
          </p>
        </div>

        {/* User Protection Action Box */}
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block">
            Your Protection Action ({policyMode})
          </span>
          <div className="flex items-center space-x-2">
            {isOverridden ? (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-purple-500/10 border border-purple-500/40 text-purple-300">
                <CheckCircle2 className="w-4 h-4" />
                <span>ACTION: USER OVERRIDE</span>
              </span>
            ) : action === 'BLOCK' ? (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-red-500/10 border border-red-500/40 text-red-400">
                <XCircle className="w-4 h-4" />
                <span>ACTION: BLOCKED</span>
              </span>
            ) : action === 'WARN' ? (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/10 border border-amber-500/40 text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                <span>ACTION: WARN / USER CHOICE</span>
              </span>
            ) : (
              <span className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/10 border border-emerald-500/40 text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>ACTION: ALLOWED</span>
              </span>
            )}
          </div>
          <p className="text-xs text-slate-400 font-sans pt-1">
            {allowlistMatch && 'Allowed by your personal Allowlist override.'}
            {blocklistMatch && 'Blocked by your personal Blocklist rule.'}
            {!allowlistMatch && !blocklistMatch && reasons[0]}
          </p>
        </div>
      </div>

      {/* Action Controls & Reversible Decisions */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-slate-800">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={handleAddAllowlist}
            disabled={isSubmitting}
            className="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-mono transition-colors disabled:opacity-50"
          >
            + Add to Allowlist
          </button>
          <button
            type="button"
            onClick={handleAddBlocklist}
            disabled={isSubmitting}
            className="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-mono transition-colors disabled:opacity-50"
          >
            + Add to Blocklist
          </button>
          {(isWarn || isBlock) && !isOverridden && (
            <button
              type="button"
              onClick={handleOverride}
              disabled={isSubmitting}
              className="px-3 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-xs font-mono transition-colors disabled:opacity-50"
            >
              Continue Anyway (Override)
            </button>
          )}
          {isOverridden && (
            <button
              type="button"
              onClick={handleRemoveOverride}
              disabled={isSubmitting}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600 text-xs font-mono transition-colors disabled:opacity-50"
            >
              Revert Override
            </button>
          )}
        </div>

        {statusMsg && (
          <span className="text-xs font-mono text-cyan-400 font-semibold animate-in fade-in">
            {statusMsg}
          </span>
        )}
      </div>
    </div>
  );
};

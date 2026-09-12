import React, { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { ArrowLeft, Calendar, Trash2, Shield, Layers } from 'lucide-react';
import { scanService } from '../services/scanService.js';
import { protectionService } from '../services/protectionService.js';
import { RiskGauge } from '../components/RiskGauge.jsx';
import { IndicatorList } from '../components/IndicatorList.jsx';
import { FeatureBreakdown } from '../components/FeatureBreakdown.jsx';
import { RiskBreakdownCard } from '../components/RiskBreakdownCard.jsx';
import { AIExplanationCard } from '../components/AIExplanationCard.jsx';
import { MLAnalysisCard } from '../components/MLAnalysisCard.jsx';
import { ThreatIntelCard } from '../components/ThreatIntelCard.jsx';
import { InvestigationTimeline } from '../components/InvestigationTimeline.jsx';
import { ProtectionDecisionCard } from '../components/ProtectionDecisionCard.jsx';
import { LoadingSpinner } from '../components/LoadingSpinner.jsx';
import { Alert } from '../components/Alert.jsx';
import { formatDate } from '../utils/formatters.js';

export const ScanDetailsPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();

  const [scan, setScan] = useState(null);
  const [protectionDecision, setProtectionDecision] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const fetchScanDetails = async () => {
      setIsLoading(true);
      setError('');
      try {
        const response = await scanService.getScanById(id);
        if (response?.data) {
          setScan(response.data);
          try {
            const evalRes = await protectionService.evaluateUrl(response.data.originalUrl, { recordAudit: false });
            if (evalRes?.data) setProtectionDecision(evalRes.data);
          } catch {
            // Non-blocking if evaluation fails
          }
        }
      } catch (err) {
        setError(err.response?.data?.message || 'Failed to retrieve scan investigation details.');
      } finally {
        setIsLoading(false);
      }
    };

    fetchScanDetails();
  }, [id]);

  const handleDelete = async () => {
    if (!window.confirm('Are you sure you want to delete this scan investigation record?')) {
      return;
    }

    setIsDeleting(true);
    try {
      await scanService.deleteScan(id);
      navigate('/history');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to delete scan record.');
      setIsDeleting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="py-24">
        <LoadingSpinner text="Retrieving forensic scan payload..." />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-4xl mx-auto px-4 py-12 space-y-4">
        <Alert type="error" message={error || 'Scan not found'} />
        <Link
          to="/history"
          className="inline-flex items-center space-x-2 text-cyan-400 hover:text-cyan-300 font-mono text-sm"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Scan Ledger</span>
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Navigation and Top Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div className="flex items-center space-x-3">
          <Link
            to="/history"
            className="p-2 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 transition-colors"
            title="Back to History"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-xl font-bold font-mono text-slate-100 flex items-center space-x-2">
              <span>Investigation Report</span>
              <span className="text-xs font-mono text-slate-500 font-normal">#{scan.scanId}</span>
            </h1>
            <p className="text-xs text-slate-400">
              Multi-engine forensic risk analysis & AI threat triage
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 self-end sm:self-auto">
          <button
            onClick={handleDelete}
            disabled={isDeleting}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-red-500/10 border border-red-500/30 hover:bg-red-500/20 text-red-400 text-xs font-mono transition-colors disabled:opacity-50"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>{isDeleting ? 'Deleting...' : 'Delete Record'}</span>
          </button>
        </div>
      </div>

      {/* Target URL Header Card */}
      <div className="p-5 rounded-xl bg-cyber-card border border-cyber-border space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Target Analyzed
          </span>
          <div className="flex items-center space-x-3 text-xs font-mono text-slate-400">
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              ThreatLens v{scan.analysisVersion || '2.0.0'}
            </span>
            <div className="flex items-center space-x-1">
              <Calendar className="w-3.5 h-3.5 text-cyan-400" />
              <span>{formatDate(scan.analyzedAt)}</span>
            </div>
          </div>
        </div>
        <div className="font-mono text-base text-cyan-300 font-semibold break-all select-all">
          {scan.originalUrl}
        </div>
        {scan.normalizedUrl !== scan.originalUrl && (
          <div className="text-xs font-mono text-slate-500 break-all">
            Normalized: {scan.normalizedUrl}
          </div>
        )}
      </div>

      {/* AI Security Explanation (Phase 2 Top Level) */}
      {scan.aiExplanation && (
        <AIExplanationCard
          aiExplanation={scan.aiExplanation}
          riskLevel={scan.riskLevel}
        />
      )}

      {/* Unified Risk Fusion Breakdown */}
      {scan.riskBreakdown && (
        <RiskBreakdownCard
          breakdown={scan.riskBreakdown}
          fusedScore={scan.riskScore}
        />
      )}

      {/* User Protection & Policy Enforcement Card (Phase 3) */}
      <ProtectionDecisionCard
        url={scan.originalUrl}
        riskScore={scan.riskScore}
        riskLevel={scan.riskLevel}
        recommendation={protectionDecision?.recommendation || (scan.riskScore >= 70 ? 'BLOCK' : scan.riskScore >= 30 ? 'WARN' : 'ALLOW')}
        action={protectionDecision?.action || (scan.riskScore >= 70 ? 'BLOCK' : scan.riskScore >= 30 ? 'WARN' : 'ALLOW')}
        policyMode={protectionDecision?.policy || 'ASK_ME'}
        userDecision={protectionDecision?.userDecision || null}
        overrideMatch={protectionDecision?.overrideMatch || false}
        reasons={protectionDecision?.reasons || []}
        allowlistMatch={protectionDecision?.allowlistMatch || false}
        blocklistMatch={protectionDecision?.blocklistMatch || false}
        onDecisionChange={async () => {
          try {
            const evalRes = await protectionService.evaluateUrl(scan.originalUrl, { recordAudit: false });
            if (evalRes?.data) setProtectionDecision(evalRes.data);
          } catch {
            // ignore
          }
        }}
      />

      {/* Score and Indicators Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1">
          <RiskGauge
            score={scan.riskScore}
            riskLevel={scan.riskLevel}
            title="Unified Risk Score"
          />
        </div>

        <div className="lg:col-span-2 bg-cyber-card p-6 rounded-xl border border-cyber-border flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide">
                  Heuristic Security Indicators ({scan.indicators?.length || 0})
                </h3>
                <span className="text-[11px] font-mono text-slate-400">9 Modular Rules</span>
              </div>
              <div className="text-right">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Heuristic Threat Score
                </span>
                <span className="font-mono font-bold text-sm text-cyan-400">
                  {scan.riskBreakdown?.heuristics?.score ?? Math.min(100, (scan.indicators || []).reduce((acc, curr) => acc + (curr.score || 0), 0))}/100
                </span>
              </div>
            </div>
            <IndicatorList indicators={scan.indicators} />
          </div>
        </div>
      </div>

      {/* Specialized Engine Cards Grid: ML + Threat Intel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {scan.ml && (
          <MLAnalysisCard ml={scan.ml} features={scan.features} />
        )}
        {scan.threatIntelligence && (
          <ThreatIntelCard threatIntel={scan.threatIntelligence} />
        )}
      </div>

      {/* Feature Breakdown Table */}
      <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide">
            Extracted Feature Vector
          </h3>
          <span className="text-xs font-mono text-slate-400">18-Feature ML Vector Contract (threatlens_features_v1.0)</span>
        </div>
        <FeatureBreakdown features={scan.features} />
      </div>

      {/* 7-Stage Investigation Timeline */}
      {scan.investigationTimeline && (
        <InvestigationTimeline timeline={scan.investigationTimeline} />
      )}
    </div>
  );
};

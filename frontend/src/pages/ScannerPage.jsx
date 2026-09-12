import React, { useState } from 'react';
import { Shield, Search, ArrowRight, Loader2, RefreshCw, AlertCircle, Link2, ExternalLink, Cpu, Sparkles, Layers } from 'lucide-react';
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
import { Alert } from '../components/Alert.jsx';
import { formatDate } from '../utils/formatters.js';

export const ScannerPage = () => {
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [protectionDecision, setProtectionDecision] = useState(null);
  const [error, setError] = useState('');

  const sampleUrls = [
    { label: 'Safe HTTPS', url: 'https://www.google.com' },
    { label: 'Raw IP + Login', url: 'http://185.10.20.30/login/verify-account' },
    { label: 'Deep Subdomains', url: 'https://login.verify.account.update.example.com' },
    { label: 'Obfuscated Encoding', url: 'https://security-verify.com/%20%2F%3F%23%25test' }
  ];

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    setError('');

    const targetUrl = urlInput.trim();
    if (!targetUrl) {
      setError('Please enter a valid URL to analyze.');
      return;
    }

    setIsScanning(true);
    setScanResult(null);
    setProtectionDecision(null);

    try {
      const [scanRes, evalRes] = await Promise.allSettled([
        scanService.scanUrl(targetUrl),
        protectionService.evaluateUrl(targetUrl)
      ]);

      if (scanRes.status === 'fulfilled' && scanRes.value?.data) {
        setScanResult(scanRes.value.data);
      } else {
        throw new Error(scanRes.reason?.response?.data?.message || 'Failed to parse scan response');
      }

      if (evalRes.status === 'fulfilled' && evalRes.value?.data) {
        setProtectionDecision(evalRes.value.data);
      }
    } catch (err) {
      const serverMsg = err.response?.data?.message || err.message || 'Error occurred while scanning URL. Please verify format.';
      setError(serverMsg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectSample = (sample) => {
    setUrlInput(sample);
    setError('');
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Hero / Header */}
      <div className="text-center max-w-3xl mx-auto space-y-3">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-xs mb-2">
          <Layers className="w-3.5 h-3.5" />
          <span>User-Controlled Protection & Explainable Defense (Phase 3)</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-extrabold text-slate-100 tracking-tight font-mono">
          Explainable URL Threat Intelligence & Protection
        </h1>
        <p className="text-sm text-slate-400 leading-relaxed">
          Inspect suspicious links with unified multi-engine fusion — combining Heuristics, Random Forest Machine Learning, VirusTotal Threat Intelligence, Generative AI Explanations, and User-Controlled Protection Policies.
        </p>
      </div>

      {/* URL Input Form */}
      <div className="max-w-4xl mx-auto bg-cyber-card p-4 sm:p-6 rounded-2xl border border-cyber-border cyber-glow">
        <Alert type="error" message={error} onClose={() => setError('')} />

        <form onSubmit={handleScan} className="space-y-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                <Link2 className="h-5 w-5 text-slate-500" />
              </div>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="Enter target URL (e.g. http://185.10.20.30/login or example.com/path)"
                className="w-full pl-11 pr-4 py-3 bg-slate-900/90 border border-slate-700 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/30 font-mono text-sm transition-all"
                disabled={isScanning}
              />
            </div>

            <button
              type="submit"
              disabled={isScanning || !urlInput.trim()}
              className="flex items-center justify-center space-x-2 px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm transition-all shadow-md hover:shadow-cyan-500/25 disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
            >
              {isScanning ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing URL...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Scan URL</span>
                </>
              )}
            </button>
          </div>

          {/* Preset quick test buttons */}
          <div className="flex flex-wrap items-center gap-2 pt-2 text-xs text-slate-400">
            <span className="font-mono text-slate-500 mr-1">Quick Samples:</span>
            {sampleUrls.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(sample.url)}
                className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 hover:border-slate-600 text-slate-300 font-mono transition-colors"
              >
                {sample.label}
              </button>
            ))}
          </div>
        </form>
      </div>

      {/* Loading State Animation */}
      {isScanning && (
        <div className="max-w-4xl mx-auto py-12">
          <div className="flex flex-col items-center justify-center space-y-4">
            <div className="relative">
              <div className="w-20 h-20 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin" />
              <div className="absolute inset-0 flex items-center justify-center">
                <Shield className="w-8 h-8 text-cyan-400 animate-pulse" />
              </div>
            </div>
            <p className="font-mono text-sm text-cyan-300 animate-pulse tracking-wide">
              Executing Multi-Engine Threat Intelligence & Synthesis Pipeline...
            </p>
          </div>
        </div>
      )}

      {/* Scan Results View */}
      {scanResult && !isScanning && (
        <div className="max-w-6xl mx-auto space-y-6 animate-in fade-in duration-300">
          {/* Target Metadata Banner */}
          <div className="flex flex-col md:flex-row md:items-center justify-between p-4 rounded-xl bg-slate-900/90 border border-cyber-border gap-3">
            <div className="space-y-1">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Target URL</span>
              <div className="font-mono text-sm text-cyan-300 font-semibold break-all">
                {scanResult.originalUrl}
              </div>
            </div>
            <div className="flex items-center space-x-3 text-xs font-mono text-slate-400 shrink-0">
              <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                ThreatLens v{scanResult.analysisVersion || '2.0.0'}
              </span>
              <span>Analyzed: {formatDate(scanResult.analyzedAt)}</span>
            </div>
          </div>

          {/* AI Security Explanation (Phase 2 Top Level) */}
          {scanResult.aiExplanation && (
            <AIExplanationCard
              aiExplanation={scanResult.aiExplanation}
              riskLevel={scanResult.riskLevel}
            />
          )}

          {/* Unified Risk Fusion Breakdown */}
          {scanResult.riskBreakdown && (
            <RiskBreakdownCard
              breakdown={scanResult.riskBreakdown}
              fusedScore={scanResult.riskScore}
            />
          )}

          {/* User Protection & Policy Enforcement Card (Phase 3) */}
          <ProtectionDecisionCard
            url={scanResult.originalUrl}
            riskScore={scanResult.riskScore}
            riskLevel={scanResult.riskLevel}
            recommendation={protectionDecision?.recommendation || (scanResult.riskScore >= 70 ? 'BLOCK' : scanResult.riskScore >= 30 ? 'WARN' : 'ALLOW')}
            action={protectionDecision?.action || (scanResult.riskScore >= 70 ? 'BLOCK' : scanResult.riskScore >= 30 ? 'WARN' : 'ALLOW')}
            policyMode={protectionDecision?.policy || 'ASK_ME'}
            userDecision={protectionDecision?.userDecision || null}
            overrideMatch={protectionDecision?.overrideMatch || false}
            reasons={protectionDecision?.reasons || []}
            allowlistMatch={protectionDecision?.allowlistMatch || false}
            blocklistMatch={protectionDecision?.blocklistMatch || false}
            onDecisionChange={async () => {
              try {
                const evalRes = await protectionService.evaluateUrl(scanResult.originalUrl, { recordAudit: false });
                if (evalRes?.data) setProtectionDecision(evalRes.data);
              } catch {
                // ignore
              }
            }}
          />

          {/* Risk Summary Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Risk Gauge Card */}
            <div className="lg:col-span-1">
              <RiskGauge
                score={scanResult.riskScore}
                riskLevel={scanResult.riskLevel}
                title="Unified Risk Score"
              />
            </div>

            {/* Security Indicators Card */}
            <div className="lg:col-span-2 bg-cyber-card p-6 rounded-xl border border-cyber-border flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide">
                      Heuristic Security Indicators ({scanResult.indicators?.length || 0})
                    </h3>
                    <span className="text-[11px] font-mono text-slate-400">9 Modular Rules</span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                      Heuristic Threat Score
                    </span>
                    <span className="font-mono font-bold text-sm text-cyan-400">
                      {scanResult.riskBreakdown?.heuristics?.score ?? Math.min(100, (scanResult.indicators || []).reduce((acc, curr) => acc + (curr.score || 0), 0))}/100
                    </span>
                  </div>
                </div>
                <IndicatorList indicators={scanResult.indicators} />
              </div>
            </div>
          </div>

          {/* Specialized Engine Cards Grid: ML + Threat Intel */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {scanResult.ml && (
              <MLAnalysisCard ml={scanResult.ml} features={scanResult.features} />
            )}
            {scanResult.threatIntelligence && (
              <ThreatIntelCard threatIntel={scanResult.threatIntelligence} />
            )}
          </div>

          {/* Extracted Features Section */}
          <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide">
                Extracted Security Features & Attributes
              </h3>
              <span className="text-xs font-mono text-slate-400">18-Feature ML Vector Contract (threatlens_features_v1.0)</span>
            </div>

            <FeatureBreakdown features={scanResult.features} />
          </div>

          {/* 7-Stage Investigation Timeline */}
          {scanResult.investigationTimeline && (
            <InvestigationTimeline timeline={scanResult.investigationTimeline} />
          )}
        </div>
      )}
    </div>
  );
};

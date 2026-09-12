import React from 'react';
import { Cpu, AlertTriangle, CheckCircle, Info, Binary } from 'lucide-react';

export const MLAnalysisCard = ({ ml, features }) => {
  if (!ml) return null;

  const isAvailable = Boolean(ml.available);
  const isMalicious = String(ml.prediction || '').toUpperCase() === 'MALICIOUS';
  const maliciousProb = typeof ml.probability === 'number'
    ? (ml.probability * 100).toFixed(1)
    : (typeof ml.score === 'number' ? ml.score.toFixed(1) : '0.0');
  const benignProb = (100 - parseFloat(maliciousProb)).toFixed(1);

  // Safely extract actual feature values from the backend response
  const urlLen = features?.urlLength ?? 0;
  const pathLen = features?.pathnameLength ?? (features?.pathname ? features.pathname.length : 0);
  const digits = features?.digitsCount !== undefined
    ? features.digitsCount
    : ((features?.normalizedUrl || features?.originalUrl || '').match(/\d/g) || []).length;
  const keywordsCount = Array.isArray(features?.detectedKeywords)
    ? features.detectedKeywords.length
    : (features?.containsSuspiciousKeyword ? 1 : 0);
  const subdomains = features?.subdomainCount !== undefined
    ? features.subdomainCount
    : (features?.subdomains ? features.subdomains.length : 0);
  const isIp = features?.isIpAddress ? 'YES' : 'NO';

  return (
    <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-mono font-bold text-slate-200 text-sm tracking-wide flex items-center space-x-2">
              <span>Machine Learning Classifier</span>
              <span className="text-[10px] font-normal px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                Random Forest v{ml.modelVersion || '1.0.0'}
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              18-Feature Lexical Classifier & Statistical Decision Ensemble
            </p>
          </div>
        </div>

        <div>
          {isAvailable ? (
            <div className="flex items-center space-x-2">
              <span
                className={`inline-flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold border ${
                  isMalicious
                    ? 'bg-red-500/10 border-red-500/40 text-red-400'
                    : 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400'
                }`}
              >
                {isMalicious ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle className="w-3.5 h-3.5" />}
                <span>PREDICTED: {String(ml.prediction || 'UNKNOWN').toUpperCase()}</span>
              </span>
            </div>
          ) : (
            <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-mono bg-slate-800 border border-slate-700 text-slate-400">
              <Info className="w-3.5 h-3.5" />
              <span>Service Offline (Graceful Fallback)</span>
            </span>
          )}
        </div>
      </div>

      {isAvailable ? (
        <div className="space-y-6">
          {/* Probability Meters */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Malicious Probability */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-red-300 flex items-center space-x-1">
                  <span className="w-2 h-2 rounded-full bg-red-400" />
                  <span>Malicious Probability</span>
                </span>
                <span className="text-red-400 font-bold text-sm">{maliciousProb}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-orange-500 to-red-500 transition-all duration-500"
                  style={{ width: `${maliciousProb}%` }}
                />
              </div>
            </div>

            {/* Benign Probability */}
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-emerald-300 flex items-center space-x-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span>Benign Probability</span>
                </span>
                <span className="text-emerald-400 font-bold text-sm">{benignProb}%</span>
              </div>
              <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-teal-500 to-emerald-500 transition-all duration-500"
                  style={{ width: `${benignProb}%` }}
                />
              </div>
            </div>
          </div>

          {/* Model Specification & Training Provenance */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Estimators</span>
              <span className="text-slate-200 font-semibold">100 Trees</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Max Depth</span>
              <span className="text-slate-200 font-semibold">15 Splits</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Schema Contract</span>
              <span className="text-cyan-400 font-semibold">{ml.schemaVersion || 'threatlens_features_v1.0'}</span>
            </div>
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Dataset Source</span>
              <span className="text-slate-200 font-semibold">Tranco + PhishTank</span>
            </div>
          </div>

          {/* Key ML Feature Vectors */}
          {features && (
            <div className="space-y-3">
              <div className="flex items-center space-x-1.5 text-xs font-mono text-slate-400">
                <Binary className="w-3.5 h-3.5 text-indigo-400" />
                <span>Key Lexical Feature Dimensions Analyzed:</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 text-xs font-mono">
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Length</span>
                  <span className="text-slate-200 font-bold">{urlLen}</span>
                </div>
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Path Length</span>
                  <span className="text-slate-200 font-bold">{pathLen}</span>
                </div>
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Digits</span>
                  <span className="text-slate-200 font-bold">{digits}</span>
                </div>
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Keywords</span>
                  <span className="text-slate-200 font-bold">{keywordsCount}</span>
                </div>
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">Subdomains</span>
                  <span className="text-slate-200 font-bold">{subdomains}</span>
                </div>
                <div className="p-2 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-[10px] text-slate-500 block">IP Host</span>
                  <span className={`font-bold ${features.isIpAddress ? 'text-amber-400' : 'text-slate-400'}`}>
                    {isIp}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 text-xs font-mono text-slate-400 space-y-2">
          <p>The Python FastAPI ML microservice is currently unreachable. The risk fusion engine automatically renormalizes weights across active engines.</p>
          <p className="text-slate-500">To enable real-time ML inference, ensure the FastAPI service is running on port 8000.</p>
        </div>
      )}
    </div>
  );
};

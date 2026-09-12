import React from 'react';
import { Shield, Info } from 'lucide-react';

export const Footer = () => {
  return (
    <footer className="mt-auto border-t border-cyber-border bg-cyber-darker/60 py-8 px-4 sm:px-6 lg:px-8 text-xs text-slate-500">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="font-mono font-semibold text-slate-300">ThreatLens AI</span>
          <span>— Explainable Cybersecurity Platform</span>
        </div>

        <div className="flex items-center space-x-1.5 text-slate-400 font-mono text-[11px] bg-slate-900/60 px-3 py-1.5 rounded-full border border-slate-800">
          <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span>
            Phase 1: Deterministic Heuristic Engine & Feature Extraction (SSRF-Safe)
          </span>
        </div>

        <div className="font-mono text-slate-600 text-[11px]">
          &copy; {new Date().getFullYear()} ThreatLens Security Systems
        </div>
      </div>
    </footer>
  );
};

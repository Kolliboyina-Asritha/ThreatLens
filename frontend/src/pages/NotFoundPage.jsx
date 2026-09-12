import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export const NotFoundPage = () => {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center px-4">
      <div className="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-400 mb-4">
        <ShieldAlert className="w-12 h-12" />
      </div>
      <h1 className="text-4xl font-bold font-mono text-slate-100">404</h1>
      <p className="text-sm font-mono text-slate-400 mt-2 mb-6">
        Requested endpoint or route does not exist.
      </p>
      <Link
        to="/scanner"
        className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Return to Scanner</span>
      </Link>
    </div>
  );
};

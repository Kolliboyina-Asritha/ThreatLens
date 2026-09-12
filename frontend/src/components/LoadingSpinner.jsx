import React from 'react';
import { Shield } from 'lucide-react';

export const LoadingSpinner = ({ text = 'Analyzing target...', size = 'md' }) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 space-y-4">
      <div className="relative">
        <div className="w-16 h-16 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin"></div>
        <div className="absolute inset-0 flex items-center justify-center">
          <Shield className="w-6 h-6 text-cyan-400 animate-pulse" />
        </div>
      </div>
      {text && <p className="text-sm font-mono text-cyan-300 animate-pulse tracking-wide">{text}</p>}
    </div>
  );
};

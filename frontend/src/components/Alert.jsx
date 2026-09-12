import React from 'react';
import { AlertCircle, CheckCircle2, Info, X } from 'lucide-react';

export const Alert = ({ type = 'error', message, onClose }) => {
  if (!message) return null;

  const styles = {
    error: 'bg-red-500/10 border-red-500/30 text-red-300',
    success: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300',
    info: 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
  };

  const icons = {
    error: <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />,
    success: <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />,
    info: <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
  };

  return (
    <div className={`flex items-start justify-between p-4 rounded-lg border ${styles[type]} mb-4 animate-in fade-in duration-200`}>
      <div className="flex items-start space-x-3">
        {icons[type]}
        <div className="text-sm">{message}</div>
      </div>
      {onClose && (
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 transition-colors ml-4"
        >
          <X className="w-4 h-4" />
        </button>
      )}
    </div>
  );
};

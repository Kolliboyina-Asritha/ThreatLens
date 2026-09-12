import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react';
import { getRiskColors } from '../utils/formatters.js';

export const RiskBadge = ({ riskLevel, showIcon = true, size = 'md' }) => {
  const colors = getRiskColors(riskLevel);

  const getIcon = () => {
    switch (riskLevel) {
      case 'SAFE':
        return <ShieldCheck className={size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
      case 'SUSPICIOUS':
        return <ShieldAlert className={size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
      case 'HIGH_RISK':
      default:
        return <ShieldX className={size === 'sm' ? 'w-3.5 h-3.5' : 'w-4 h-4'} />;
    }
  };

  const getLabel = () => {
    switch (riskLevel) {
      case 'SAFE':
        return 'SAFE';
      case 'SUSPICIOUS':
        return 'SUSPICIOUS';
      case 'HIGH_RISK':
      default:
        return 'HIGH RISK';
    }
  };

  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm';

  return (
    <span
      className={`inline-flex items-center space-x-1.5 rounded-full font-mono font-medium border ${colors.badgeBg} ${sizeClasses}`}
    >
      {showIcon && getIcon()}
      <span>{getLabel()}</span>
    </span>
  );
};

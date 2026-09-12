import React from 'react';
import { Globe, Shield, Hash, Layers, Lock, Unlock } from 'lucide-react';

export const FeatureBreakdown = ({ features }) => {
  if (!features) return null;

  const items = [
    {
      label: 'Protocol',
      value: features.protocol?.toUpperCase() || '—',
      icon: features.usesHttps ? <Lock className="w-4 h-4 text-emerald-400" /> : <Unlock className="w-4 h-4 text-amber-400" />,
      highlight: !features.usesHttps
    },
    {
      label: 'Hostname',
      value: features.hostname || '—',
      icon: <Globe className="w-4 h-4 text-cyan-400" />
    },
    {
      label: 'Host is IP Address',
      value: features.isIpAddress ? 'YES' : 'NO',
      icon: <Shield className="w-4 h-4 text-slate-400" />,
      highlight: features.isIpAddress
    },
    {
      label: 'HTTPS Encrypted',
      value: features.usesHttps ? 'YES' : 'NO',
      icon: <Lock className="w-4 h-4 text-slate-400" />,
      highlight: !features.usesHttps
    },
    {
      label: 'URL Total Length',
      value: `${features.urlLength || 0} chars`,
      icon: <Hash className="w-4 h-4 text-slate-400" />,
      highlight: features.urlLength > 80
    },
    {
      label: 'Subdomain Count',
      value: features.subdomainCount !== undefined ? features.subdomainCount : (features.subdomains ? features.subdomains.length : 0),
      icon: <Layers className="w-4 h-4 text-slate-400" />,
      highlight: (features.subdomainCount || 0) >= 3
    },
    {
      label: 'Special Characters',
      value: features.specialCharacterCount || 0,
      icon: <Hash className="w-4 h-4 text-slate-400" />,
      highlight: (features.specialCharacterCount || 0) >= 6
    },
    {
      label: 'Path Segments',
      value: features.pathSegmentCount || 0,
      icon: <Layers className="w-4 h-4 text-slate-400" />
    },
    {
      label: 'Query Parameters',
      value: features.queryParamsCount || 0,
      icon: <Hash className="w-4 h-4 text-slate-400" />
    },
    {
      label: 'Percent Encoded',
      value: `${features.percentCount || 0} sequences`,
      icon: <Hash className="w-4 h-4 text-slate-400" />,
      highlight: (features.percentCount || 0) > 0
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
      {items.map((item, idx) => (
        <div
          key={idx}
          className={`p-3.5 rounded-lg border bg-cyber-card transition-all ${
            item.highlight
              ? 'border-amber-500/40 bg-amber-500/5 text-amber-200'
              : 'border-cyber-border text-slate-300'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>{item.label}</span>
            {item.icon}
          </div>
          <div className="font-mono font-semibold text-sm truncate">
            {item.value}
          </div>
        </div>
      ))}
    </div>
  );
};

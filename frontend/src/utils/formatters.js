/**
 * Formats a Date object or ISO string into a readable timestamp.
 * @param {string|Date} dateInput
 * @returns {string}
 */
export const formatDate = (dateInput) => {
  if (!dateInput) return '—';
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return '—';
  
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(d);
};

/**
 * Truncates a URL with ellipsis if it exceeds maxLength.
 * @param {string} url
 * @param {number} maxLength
 * @returns {string}
 */
export const truncateUrl = (url, maxLength = 45) => {
  if (!url) return '';
  if (url.length <= maxLength) return url;
  return `${url.substring(0, maxLength)}...`;
};

/**
 * Returns Tailwind color classes based on risk level.
 * @param {string} riskLevel
 * @returns {object}
 */
export const getRiskColors = (riskLevel) => {
  switch (riskLevel) {
    case 'SAFE':
      return {
        badgeBg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
        text: 'text-emerald-400',
        border: 'border-emerald-500/40',
        bg: 'bg-emerald-500/10',
        glow: 'cyber-glow-safe',
        progress: 'bg-emerald-500'
      };
    case 'SUSPICIOUS':
      return {
        badgeBg: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
        text: 'text-amber-400',
        border: 'border-amber-500/40',
        bg: 'bg-amber-500/10',
        glow: 'cyber-glow-suspicious',
        progress: 'bg-amber-500'
      };
    case 'HIGH_RISK':
    default:
      return {
        badgeBg: 'bg-red-500/10 border-red-500/30 text-red-400',
        text: 'text-red-400',
        border: 'border-red-500/40',
        bg: 'bg-red-500/10',
        glow: 'cyber-glow-danger',
        progress: 'bg-red-500'
      };
  }
};

/**
 * Returns severity badge styles for indicators.
 * @param {string} severity
 * @returns {string}
 */
export const getSeverityStyle = (severity) => {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-rose-500/20 text-rose-300 border-rose-500/50';
    case 'HIGH':
      return 'bg-red-500/20 text-red-300 border-red-500/50';
    case 'MEDIUM':
      return 'bg-amber-500/20 text-amber-300 border-amber-500/50';
    case 'LOW':
    default:
      return 'bg-blue-500/20 text-blue-300 border-blue-500/50';
  }
};

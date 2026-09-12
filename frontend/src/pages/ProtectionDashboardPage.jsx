import React, { useState, useEffect } from 'react';
import {
  Shield,
  Sliders,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Plus,
  Trash2,
  RefreshCw,
  Search,
  Filter,
  Layers,
  ArrowRight,
  Sparkles,
  Info
} from 'lucide-react';
import { protectionService } from '../services/protectionService.js';
import { DualTierExplainer } from '../components/DualTierExplainer.jsx';
import { LoadingSpinner } from '../components/LoadingSpinner.jsx';
import { Alert } from '../components/Alert.jsx';
import { formatDate } from '../utils/formatters.js';

export const ProtectionDashboardPage = () => {
  const [policy, setPolicy] = useState(null);
  const [stats, setStats] = useState(null);
  const [events, setEvents] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  // Policy edit state
  const [selectedMode, setSelectedMode] = useState('ASK_ME');
  const [customAllowMax, setCustomAllowMax] = useState(29);
  const [customWarnMax, setCustomWarnMax] = useState(69);
  const [isSavingPolicy, setIsSavingPolicy] = useState(false);

  // List management state
  const [activeTab, setActiveTab] = useState('allowlist');
  const [newEntryVal, setNewEntryVal] = useState('');
  const [newEntryType, setNewEntryType] = useState('DOMAIN');
  const [isAddingEntry, setIsAddingEntry] = useState(false);

  // Events filter state
  const [eventFilterAction, setEventFilterAction] = useState('ALL');
  const [eventFilterRisk, setEventFilterRisk] = useState('ALL');

  // Quick Evaluator State
  const [testUrl, setTestUrl] = useState('');
  const [evalResult, setEvalResult] = useState(null);
  const [isEvaluating, setIsEvaluating] = useState(false);

  const fetchData = async () => {
    setIsLoading(true);
    setError('');
    try {
      const [policyRes, statsRes, eventsRes] = await Promise.all([
        protectionService.getPolicy(),
        protectionService.getStats(),
        protectionService.getEvents({ limit: 15 })
      ]);

      if (policyRes?.data) {
        setPolicy(policyRes.data);
        setSelectedMode(policyRes.data.mode || 'ASK_ME');
        setCustomAllowMax(policyRes.data.customThresholds?.allowMax ?? 29);
        setCustomWarnMax(policyRes.data.customThresholds?.warnMax ?? 69);
      }
      if (statsRes?.data) setStats(statsRes.data);
      if (eventsRes?.data) setEvents(eventsRes.data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load protection settings.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleSavePolicy = async (e) => {
    if (e) e.preventDefault();
    setIsSavingPolicy(true);
    setError('');
    setSuccessMsg('');

    if (selectedMode === 'CUSTOM' && customAllowMax >= customWarnMax) {
      setError('AllowMax threshold must be strictly less than WarnMax threshold.');
      setIsSavingPolicy(false);
      return;
    }

    try {
      const res = await protectionService.updatePolicy({
        mode: selectedMode,
        customThresholds: {
          allowMax: Number(customAllowMax),
          warnMax: Number(customWarnMax)
        }
      });
      setPolicy(res.data);
      setSuccessMsg('Protection policy updated successfully.');
      fetchData();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update policy.');
    } finally {
      setIsSavingPolicy(false);
    }
  };

  const handleAddListEntry = async (e) => {
    if (e) e.preventDefault();
    if (!newEntryVal.trim()) return;

    setIsAddingEntry(true);
    setError('');
    setSuccessMsg('');

    try {
      if (activeTab === 'allowlist') {
        const res = await protectionService.addAllowlistEntry(newEntryVal.trim(), newEntryType);
        setPolicy((prev) => ({ ...prev, allowlist: res.data }));
        setSuccessMsg(`Added "${newEntryVal.trim()}" to trusted Allowlist.`);
      } else {
        const res = await protectionService.addBlocklistEntry(newEntryVal.trim(), newEntryType);
        setPolicy((prev) => ({ ...prev, blocklist: res.data }));
        setSuccessMsg(`Added "${newEntryVal.trim()}" to personal Blocklist.`);
      }
      setNewEntryVal('');
      fetchData();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to add entry.');
    } finally {
      setIsAddingEntry(false);
    }
  };

  const handleRemoveEntry = async (id, type) => {
    setError('');
    setSuccessMsg('');
    try {
      if (type === 'allowlist') {
        const res = await protectionService.removeAllowlistEntry(id);
        setPolicy((prev) => ({ ...prev, allowlist: res.data }));
        setSuccessMsg('Entry removed from Allowlist.');
      } else {
        const res = await protectionService.removeBlocklistEntry(id);
        setPolicy((prev) => ({ ...prev, blocklist: res.data }));
        setSuccessMsg('Entry unblocked and removed from Blocklist.');
      }
      fetchData();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to remove entry.');
    }
  };

  const handleQuickEvaluate = async (e) => {
    if (e) e.preventDefault();
    if (!testUrl.trim()) return;

    setIsEvaluating(true);
    setEvalResult(null);
    try {
      const res = await protectionService.evaluateUrl(testUrl.trim());
      setEvalResult(res.data);
      fetchData(); // refresh events
    } catch (err) {
      setError(err.response?.data?.message || 'Evaluation failed.');
    } finally {
      setIsEvaluating(false);
    }
  };

  if (isLoading && !policy) {
    return (
      <div className="py-24">
        <LoadingSpinner text="Loading user protection settings..." />
      </div>
    );
  }

  const modes = [
    {
      id: 'ASK_ME',
      name: 'Ask Me (Advisory)',
      desc: 'Never automatically blocks. Shows ThreatLens recommendation and lets you choose.',
      color: 'border-cyan-500/40 text-cyan-300'
    },
    {
      id: 'BALANCED',
      name: 'Balanced (Recommended)',
      desc: 'Allows safe (<30), warns on suspicious (30–69), blocks high-risk threats (>=70).',
      color: 'border-emerald-500/40 text-emerald-300'
    },
    {
      id: 'STRICT',
      name: 'Strict (High Security)',
      desc: 'Automatically enforces blocking on all high-risk threats and surfaces warnings on any suspicious indicators.',
      color: 'border-purple-500/40 text-purple-300'
    },
    {
      id: 'CUSTOM',
      name: 'Custom Thresholds',
      desc: 'User-configured numerical risk score boundaries for Allow, Warn, and Block.',
      color: 'border-amber-500/40 text-amber-300'
    }
  ];

  const filteredEvents = events.filter((e) => {
    if (eventFilterAction !== 'ALL' && e.action !== eventFilterAction) return false;
    if (eventFilterRisk !== 'ALL' && e.riskLevel !== eventFilterRisk) return false;
    return true;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-cyber-border pb-6">
        <div>
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-xs mb-2">
            <Shield className="w-3.5 h-3.5" />
            <span>User-Controlled Protection & Policy Layer (Phase 3)</span>
          </div>
          <h1 className="text-3xl font-extrabold text-slate-100 tracking-tight font-mono">
            Protection Dashboard & Policies
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            ThreatLens detects threats and provides recommendations. You control enforcement.
          </p>
        </div>

        <button
          onClick={fetchData}
          className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-500 text-slate-300 text-xs font-mono transition-colors self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Data</span>
        </button>
      </div>

      <Alert type="error" message={error} onClose={() => setError('')} />
      <Alert type="success" message={successMsg} onClose={() => setSuccessMsg('')} />

      {/* 1. Statistics Cards */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          <div className="p-4 rounded-xl bg-cyber-card border border-cyber-border">
            <span className="text-[10px] font-mono text-slate-400 uppercase block">Total Analyzed</span>
            <span className="text-2xl font-bold font-mono text-slate-100">{stats.totalAnalyzed}</span>
          </div>
          <div className="p-4 rounded-xl bg-cyber-card border border-emerald-500/30">
            <span className="text-[10px] font-mono text-emerald-400 uppercase block">Allowed</span>
            <span className="text-2xl font-bold font-mono text-emerald-400">{stats.allowed}</span>
          </div>
          <div className="p-4 rounded-xl bg-cyber-card border border-amber-500/30">
            <span className="text-[10px] font-mono text-amber-400 uppercase block">Warnings Shown</span>
            <span className="text-2xl font-bold font-mono text-amber-400">{stats.warned}</span>
          </div>
          <div className="p-4 rounded-xl bg-cyber-card border border-red-500/30">
            <span className="text-[10px] font-mono text-red-400 uppercase block">URLs Blocked</span>
            <span className="text-2xl font-bold font-mono text-red-400">{stats.blocked}</span>
          </div>
          <div className="p-4 rounded-xl bg-cyber-card border border-purple-500/30">
            <span className="text-[10px] font-mono text-purple-300 uppercase block">User Overrides</span>
            <span className="text-2xl font-bold font-mono text-purple-300">{stats.overrides}</span>
          </div>
          <div className="p-4 rounded-xl bg-cyber-card border border-cyan-500/30">
            <span className="text-[10px] font-mono text-cyan-300 uppercase block">Active Lists</span>
            <span className="text-sm font-bold font-mono text-cyan-300">
              {stats.allowlistCount} Allow / {stats.blocklistCount} Block
            </span>
          </div>
        </div>
      )}

      {/* 2. Protection Policy Configuration */}
      <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-2">
            <Sliders className="w-5 h-5 text-cyan-400" />
            <h3 className="font-mono font-bold text-slate-100 text-sm tracking-wide">
              Active Protection Policy Mode
            </h3>
          </div>
          <DualTierExplainer
            conceptKey={`${selectedMode}_MODE`}
            fallbackTitle={`${selectedMode} Mode`}
            buttonLabel="Explain Mode"
          />
        </div>

        <form onSubmit={handleSavePolicy} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {modes.map((mode) => {
              const isSelected = selectedMode === mode.id;
              return (
                <div
                  key={mode.id}
                  onClick={() => setSelectedMode(mode.id)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? `bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/50`
                      : 'bg-slate-950/50 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs font-bold text-slate-200">{mode.name}</span>
                    <input
                      type="radio"
                      name="protectionMode"
                      value={mode.id}
                      checked={isSelected}
                      onChange={() => setSelectedMode(mode.id)}
                      className="text-cyan-500 focus:ring-cyan-500"
                    />
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{mode.desc}</p>
                </div>
              );
            })}
          </div>

          {/* Custom Threshold Sliders (Visible when CUSTOM is selected) */}
          {selectedMode === 'CUSTOM' && (
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between text-xs font-mono text-slate-300">
                <span>Custom Threshold Settings</span>
                <span className="text-amber-400 text-[11px]">
                  Allow &le; {customAllowMax} | Warn {customAllowMax + 1}&ndash;{customWarnMax} | Block &gt; {customWarnMax}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-mono text-slate-400">
                    <span>Allow Max Threshold:</span>
                    <span className="text-emerald-400 font-bold">{customAllowMax}</span>
                  </div>
                  <input
                    type="range"
                    min="0"
                    max="98"
                    value={customAllowMax}
                    onChange={(e) => setCustomAllowMax(Number(e.target.value))}
                    className="w-full accent-cyan-500"
                  />
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between text-xs font-mono text-slate-400">
                    <span>Warn Max Threshold:</span>
                    <span className="text-amber-400 font-bold">{customWarnMax}</span>
                  </div>
                  <input
                    type="range"
                    min={customAllowMax + 1}
                    max="100"
                    value={customWarnMax}
                    onChange={(e) => setCustomWarnMax(Number(e.target.value))}
                    className="w-full accent-amber-500"
                  />
                </div>
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={isSavingPolicy}
              className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-all shadow-md disabled:opacity-50"
            >
              {isSavingPolicy ? 'Saving Policy...' : 'Apply Protection Setting'}
            </button>
          </div>
        </form>
      </div>

      {/* 3. Reversible Allowlist & Blocklist Management */}
      <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <h3 className="font-mono font-bold text-slate-100 text-sm tracking-wide">
              Reversible User Allowlist & Blocklist
            </h3>
          </div>

          {/* Tabs */}
          <div className="flex items-center space-x-2 bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              type="button"
              onClick={() => setActiveTab('allowlist')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition-colors ${
                activeTab === 'allowlist'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Trusted Allowlist ({policy?.allowlist?.length || 0})
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('blocklist')}
              className={`px-3 py-1.5 rounded-md text-xs font-mono font-semibold transition-colors ${
                activeTab === 'blocklist'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Personal Blocklist ({policy?.blocklist?.length || 0})
            </button>
          </div>
        </div>

        {/* Add Entry Form */}
        <form onSubmit={handleAddListEntry} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={newEntryVal}
            onChange={(e) => setNewEntryVal(e.target.value)}
            placeholder={
              activeTab === 'allowlist'
                ? 'Enter domain or URL to allow (e.g. internal-portal.org or example.com)'
                : 'Enter domain or URL to block (e.g. phishing-site.net or 185.10.20.30)'
            }
            className="flex-1 px-4 py-2.5 bg-slate-900 border border-slate-700 rounded-xl text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
          />

          <select
            value={newEntryType}
            onChange={(e) => setNewEntryType(e.target.value)}
            className="px-3 py-2.5 bg-slate-900 border border-slate-700 rounded-xl text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="DOMAIN">DOMAIN</option>
            <option value="URL">FULL URL</option>
          </select>

          <button
            type="submit"
            disabled={isAddingEntry || !newEntryVal.trim()}
            className={`flex items-center justify-center space-x-1.5 px-4 py-2.5 rounded-xl font-bold text-xs font-mono transition-all disabled:opacity-50 ${
              activeTab === 'allowlist'
                ? 'bg-emerald-500 hover:bg-emerald-400 text-slate-950'
                : 'bg-red-500 hover:bg-red-400 text-slate-950'
            }`}
          >
            <Plus className="w-4 h-4" />
            <span>{activeTab === 'allowlist' ? 'Allow Site' : 'Block Site'}</span>
          </button>
        </form>

        {/* List Entries Table */}
        <div className="overflow-x-auto">
          {activeTab === 'allowlist' ? (
            policy?.allowlist?.length > 0 ? (
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2.5 px-3">Entry Value</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Added Date</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {policy.allowlist.map((item) => (
                    <tr key={item._id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-3 text-emerald-300 font-semibold">{item.value}</td>
                      <td className="py-3 px-3 text-slate-400">{item.type}</td>
                      <td className="py-3 px-3 text-slate-500">{formatDate(item.addedAt)}</td>
                      <td className="py-3 px-3 text-right">
                        <button
                          type="button"
                          onClick={() => handleRemoveEntry(item._id, 'allowlist')}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-red-500/20 text-slate-400 hover:text-red-400 border border-slate-700 transition-colors text-[11px]"
                        >
                          Remove from Allowlist
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="text-xs font-mono text-slate-500 italic py-4 text-center">
                No entries in your trusted allowlist. Trusted sites bypass automated blocking.
              </p>
            )
          ) : policy?.blocklist?.length > 0 ? (
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Entry Value</th>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Added Date</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {policy.blocklist.map((item) => (
                  <tr key={item._id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-3 text-red-400 font-semibold">{item.value}</td>
                    <td className="py-3 px-3 text-slate-400">{item.type}</td>
                    <td className="py-3 px-3 text-slate-500">{formatDate(item.addedAt)}</td>
                    <td className="py-3 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => handleRemoveEntry(item._id, 'blocklist')}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-emerald-500/20 text-slate-400 hover:text-emerald-400 border border-slate-700 transition-colors text-[11px]"
                      >
                        Unblock Site
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-xs font-mono text-slate-500 italic py-4 text-center">
              No entries in your blocklist. Blocklisted sites are immediately blocked.
            </p>
          )}
        </div>
      </div>

      {/* 4. Quick Protection Evaluator Testing Tool */}
      <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-cyan-400" />
            <h3 className="font-mono font-bold text-slate-100 text-sm tracking-wide">
              Live Protection Policy Evaluator
            </h3>
          </div>
          <span className="text-xs font-mono text-slate-400">Test policy & precedence in real-time</span>
        </div>

        <form onSubmit={handleQuickEvaluate} className="flex gap-3">
          <input
            type="text"
            value={testUrl}
            onChange={(e) => setTestUrl(e.target.value)}
            placeholder="Enter URL to test (e.g. http://185.10.20.30/login/verify-account or https://google.com)"
            className="flex-1 px-4 py-3 bg-slate-900 border border-slate-700 rounded-xl text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
          />
          <button
            type="submit"
            disabled={isEvaluating || !testUrl.trim()}
            className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-all disabled:opacity-50"
          >
            {isEvaluating ? 'Evaluating...' : 'Evaluate Decision'}
          </button>
        </form>

        {evalResult && (
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 animate-in fade-in">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
              <span className="font-mono text-xs font-bold text-slate-200">
                Target: {evalResult.url}
              </span>
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono text-slate-400">
                  Risk Score: <strong className="text-slate-100">{evalResult.riskScore}/100</strong>
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 text-slate-300">
                  {evalResult.riskLevel}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">ThreatLens Recommendation</span>
                <span
                  className={`font-bold ${
                    evalResult.recommendation === 'BLOCK'
                      ? 'text-red-400'
                      : evalResult.recommendation === 'WARN'
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {evalResult.recommendation}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                <span className="text-slate-500 block text-[10px] uppercase">Enforced Action ({evalResult.policy})</span>
                <span
                  className={`font-bold ${
                    evalResult.userDecision === 'OVERRIDE' || evalResult.overrideMatch
                      ? 'text-purple-300'
                      : evalResult.action === 'BLOCK'
                      ? 'text-red-400'
                      : evalResult.action === 'WARN'
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {evalResult.userDecision === 'OVERRIDE' || evalResult.overrideMatch ? 'ALLOW (USER OVERRIDE)' : evalResult.action} {evalResult.requiresUserConfirmation && evalResult.userDecision !== 'OVERRIDE' ? '(Awaiting User Choice)' : ''}
                </span>
              </div>
            </div>

            {evalResult.reasons?.length > 0 && (
              <div className="text-xs text-slate-400 font-mono">
                <span className="text-slate-500">Decision Rationale: </span>
                <span>{evalResult.reasons.join(' ')}</span>
              </div>
            )}

            {(evalResult.action === 'WARN' || evalResult.action === 'BLOCK' || evalResult.recommendation === 'BLOCK') && evalResult.userDecision !== 'OVERRIDE' && !evalResult.overrideMatch && (
              <div className="pt-2 border-t border-slate-800 flex justify-end">
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await protectionService.recordOverride(evalResult.url, 'Live evaluator manual override');
                      const fresh = await protectionService.evaluateUrl(evalResult.url, { recordAudit: false });
                      setEvalResult(fresh.data);
                      fetchData();
                    } catch (e) {
                      setError('Failed to record override');
                    }
                  }}
                  className="px-3 py-1.5 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 text-xs font-mono transition-colors"
                >
                  Continue Anyway (Override)
                </button>
              </div>
            )}

            {(evalResult.userDecision === 'OVERRIDE' || evalResult.overrideMatch) && (
              <div className="pt-2 border-t border-slate-800 flex justify-end">
                <button
                  type="button"
                  onClick={async () => {
                    try {
                      await protectionService.removeOverride(encodeURIComponent(evalResult.url));
                      const fresh = await protectionService.evaluateUrl(evalResult.url, { recordAudit: false });
                      setEvalResult(fresh.data);
                      fetchData();
                    } catch (e) {
                      setError('Failed to revert override');
                    }
                  }}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-600 text-xs font-mono transition-colors"
                >
                  Revert Override
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 5. Recent Security Events Audit Ledger */}
      <div className="bg-cyber-card p-6 rounded-xl border border-cyber-border space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div className="flex items-center space-x-2">
            <Filter className="w-5 h-5 text-cyan-400" />
            <h3 className="font-mono font-bold text-slate-100 text-sm tracking-wide">
              Recent Security & Enforcement Events
            </h3>
          </div>

          <div className="flex items-center space-x-2">
            <select
              value={eventFilterAction}
              onChange={(e) => setEventFilterAction(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-slate-300 font-mono text-xs focus:outline-none"
            >
              <option value="ALL">All Actions</option>
              <option value="ALLOW">ALLOW</option>
              <option value="WARN">WARN</option>
              <option value="BLOCK">BLOCK</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          {filteredEvents.length > 0 ? (
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Target URL</th>
                  <th className="py-2.5 px-3">Risk</th>
                  <th className="py-2.5 px-3">Recommendation</th>
                  <th className="py-2.5 px-3">Policy Action</th>
                  <th className="py-2.5 px-3">User Decision</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEvents.map((ev) => (
                  <tr key={ev._id} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-3 text-slate-500 whitespace-nowrap">{formatDate(ev.createdAt)}</td>
                    <td className="py-3 px-3 text-slate-200 font-semibold max-w-xs truncate" title={ev.url}>
                      {ev.url}
                    </td>
                    <td className="py-3 px-3">
                      <span className="font-bold text-slate-300">{ev.riskScore}/100</span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`font-semibold ${
                          ev.recommendation === 'BLOCK'
                            ? 'text-red-400'
                            : ev.recommendation === 'WARN'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {ev.recommendation}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`font-semibold ${
                          ev.action === 'BLOCK'
                            ? 'text-red-400'
                            : ev.action === 'WARN'
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {ev.action} ({ev.policyMode})
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      {ev.userDecision ? (
                        <span className="px-2 py-0.5 rounded text-[10px] bg-purple-500/10 text-purple-300 border border-purple-500/30 font-bold">
                          {ev.userDecision}
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="text-xs font-mono text-slate-500 italic py-6 text-center">
              No security events recorded matching the current filter.
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

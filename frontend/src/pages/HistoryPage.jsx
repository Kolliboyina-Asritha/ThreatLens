import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { History, Trash2, ExternalLink, ChevronLeft, ChevronRight, AlertCircle, RefreshCw, Shield } from 'lucide-react';
import { scanService } from '../services/scanService.js';
import { RiskBadge } from '../components/RiskBadge.jsx';
import { LoadingSpinner } from '../components/LoadingSpinner.jsx';
import { Alert } from '../components/Alert.jsx';
import { formatDate, truncateUrl } from '../utils/formatters.js';

export const HistoryPage = () => {
  const [scans, setScans] = useState([]);
  const [meta, setMeta] = useState({
    page: 1,
    limit: 10,
    totalPages: 1,
    totalCount: 0,
    hasNextPage: false,
    hasPrevPage: false
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleteLoadingId, setDeleteLoadingId] = useState(null);

  const fetchScans = useCallback(async (page = 1) => {
    setIsLoading(true);
    setError('');
    try {
      const response = await scanService.getScans(page, 10);
      if (response?.data) {
        setScans(response.data);
        if (response.meta) {
          setMeta(response.meta);
        }
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load scan history.');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans(1);
  }, [fetchScans]);

  const handleDelete = async (e, scanId) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to remove this scan from your history?')) {
      return;
    }

    setDeleteLoadingId(scanId);
    try {
      await scanService.deleteScan(scanId);
      // If last item on page > 1, go back one page
      const nextPage = scans.length === 1 && meta.page > 1 ? meta.page - 1 : meta.page;
      await fetchScans(nextPage);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to delete scan record.');
    } finally {
      setDeleteLoadingId(null);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <History className="w-6 h-6 text-cyan-400" />
            <h1 className="text-2xl font-bold font-mono text-slate-100">Scan Audit Ledger</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Chronological log of all URL threat investigations performed by your account
          </p>
        </div>

        <button
          onClick={() => fetchScans(meta.page)}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-600 text-xs font-mono text-slate-300 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <Alert type="error" message={error} onClose={() => setError('')} />

      {/* Main Content Area */}
      {isLoading ? (
        <div className="py-16">
          <LoadingSpinner text="Retrieving audit history..." />
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-cyber-card border border-cyber-border rounded-xl p-12 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-500">
            <Shield className="w-6 h-6" />
          </div>
          <h3 className="text-lg font-mono font-semibold text-slate-200">No Scan Records Found</h3>
          <p className="text-xs text-slate-400 max-w-sm mx-auto">
            You have not analyzed any URLs yet. Use the scanner to evaluate your first target.
          </p>
          <Link
            to="/scanner"
            className="inline-flex items-center space-x-2 px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs rounded-lg transition-colors"
          >
            <span>Launch Scanner</span>
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Table Container */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl overflow-hidden shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-900/80 text-xs font-mono uppercase tracking-wider text-slate-400 border-b border-cyber-border">
                  <tr>
                    <th className="py-3.5 px-4 font-medium">Target URL</th>
                    <th className="py-3.5 px-4 font-medium text-center">Score</th>
                    <th className="py-3.5 px-4 font-medium text-center">Risk Level</th>
                    <th className="py-3.5 px-4 font-medium">Indicators</th>
                    <th className="py-3.5 px-4 font-medium">Analyzed At</th>
                    <th className="py-3.5 px-4 font-medium text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                  {scans.map((scan) => (
                    <tr
                      key={scan.id}
                      className="hover:bg-slate-800/40 transition-colors group"
                    >
                      <td className="py-3.5 px-4 max-w-xs sm:max-w-md">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="font-medium text-slate-200 hover:text-cyan-400 transition-colors block truncate"
                          title={scan.originalUrl}
                        >
                          {truncateUrl(scan.originalUrl, 50)}
                        </Link>
                      </td>
                      <td className="py-3.5 px-4 text-center font-bold">
                        <span className="text-slate-100">{scan.riskScore}</span>
                        <span className="text-slate-500 text-[10px]">/100</span>
                      </td>
                      <td className="py-3.5 px-4 text-center">
                        <RiskBadge riskLevel={scan.riskLevel} size="sm" />
                      </td>
                      <td className="py-3.5 px-4 text-slate-400">
                        {scan.indicatorCount} flagged
                      </td>
                      <td className="py-3.5 px-4 text-slate-400">
                        {formatDate(scan.createdAt)}
                      </td>
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end space-x-2">
                          <Link
                            to={`/scans/${scan.id}`}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-400 transition-colors"
                            title="View Investigation Details"
                          >
                            <ExternalLink className="w-3.5 h-3.5" />
                          </Link>
                          <button
                            onClick={(e) => handleDelete(e, scan.id)}
                            disabled={deleteLoadingId === scan.id}
                            className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition-colors disabled:opacity-50"
                            title="Delete Scan Record"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination Controls */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-slate-400 pt-2">
            <div>
              Showing <span className="text-slate-200">{(meta.page - 1) * meta.limit + 1}</span> to{' '}
              <span className="text-slate-200">
                {Math.min(meta.page * meta.limit, meta.totalCount)}
              </span>{' '}
              of <span className="text-slate-200">{meta.totalCount}</span> scans
            </div>

            <div className="flex items-center space-x-2">
              <button
                onClick={() => fetchScans(meta.page - 1)}
                disabled={!meta.hasPrevPage || isLoading}
                className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
                <span>Prev</span>
              </button>
              <span className="px-2">
                Page {meta.page} of {meta.totalPages || 1}
              </span>
              <button
                onClick={() => fetchScans(meta.page + 1)}
                disabled={!meta.hasNextPage || isLoading}
                className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300 transition-colors"
              >
                <span>Next</span>
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

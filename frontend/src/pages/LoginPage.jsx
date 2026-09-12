import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Shield, Lock, Mail, ArrowRight, Loader2, CheckCircle2, Layers, UserCheck, RefreshCw } from 'lucide-react';
import { useAuth } from '../hooks/useAuth.js';
import { authService } from '../services/authService.js';
import { Alert } from '../components/Alert.jsx';

export const LoginPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [extensionLinked, setExtensionLinked] = useState(false);
  const [isLinkingExtension, setIsLinkingExtension] = useState(false);

  const { user, login, logout } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const handoffExecutedRef = useRef(false);

  const extId = searchParams.get('extId');
  const extState = searchParams.get('state');
  const isExtensionFlow = Boolean(extId && extState);

  const performExtensionHandoff = async () => {
    if (!extId || !extState || handoffExecutedRef.current) return;
    handoffExecutedRef.current = true;
    setIsLinkingExtension(true);
    setError('');
    try {
      const res = await authService.authorizeExtension(extId, extState);
      const authCode = res.data?.authCode;

      if (authCode && window.chrome && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage(
          extId,
          {
            type: 'THREATLENS_AUTH_CODE',
            authCode,
            state: extState
          },
          (response) => {
            if (chrome.runtime.lastError) {
              console.warn('[ThreatLens] Extension message notice:', chrome.runtime.lastError.message);
              setError(`Extension communication failed: ${chrome.runtime.lastError.message}`);
              handoffExecutedRef.current = false;
              setIsLinkingExtension(false);
              return;
            }
            if (response && response.success) {
              setExtensionLinked(true);
            } else {
              setError(response?.error || 'Failed to link extension');
              handoffExecutedRef.current = false;
            }
            setIsLinkingExtension(false);
          }
        );
      } else {
        setError('ThreatLens Chrome Extension is not detected or supported in this browser.');
        setIsLinkingExtension(false);
      }
    } catch (err) {
      console.warn('[ThreatLens] Extension handoff notice:', err);
      setError(err?.response?.data?.message || 'Failed to authorize extension session.');
      handoffExecutedRef.current = false; // Allow retry on failure
      setIsLinkingExtension(false);
    }
  };

  // If user is already logged in and arrived with an extension auth request
  useEffect(() => {
    if (user && isExtensionFlow && !extensionLinked && !isLinkingExtension && !handoffExecutedRef.current) {
      performExtensionHandoff();
    }
  }, [user, isExtensionFlow]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!email || !password) {
      setError('Please provide both email and password.');
      return;
    }

    setIsSubmitting(true);
    try {
      await login(email, password);
      if (isExtensionFlow) {
        await performExtensionHandoff();
      } else {
        navigate('/scanner');
      }
    } catch (err) {
      const serverMsg = err.response?.data?.message || 'Authentication failed. Please check your credentials.';
      setError(serverMsg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4 sm:px-6 lg:px-8 py-12">
      <div className="max-w-md w-full space-y-8 bg-cyber-card p-8 rounded-2xl border border-cyber-border cyber-glow">
        <div className="text-center">
          <div className="inline-flex p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 mb-4">
            <Shield className="w-8 h-8 text-cyan-400" />
          </div>
          <h2 className="text-2xl font-bold text-slate-100 tracking-tight font-mono">
            {isExtensionFlow && user ? 'Authorize Extension' : 'Sign In to ThreatLens'}
          </h2>
          <p className="text-xs text-slate-400 mt-2">
            {isExtensionFlow && user
              ? 'Connecting your browser extension to your active ThreatLens account'
              : 'Access your explainable URL threat detection dashboard'}
          </p>
        </div>

        {/* Extension Linking Banner (for unauthenticated or pending state) */}
        {isExtensionFlow && !extensionLinked && (
          <div className="p-3.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center space-x-2.5">
            <Layers className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>Connecting to ThreatLens Chrome Browser Extension...</span>
          </div>
        )}

        {/* Extension Successfully Linked Confirmation */}
        {extensionLinked && (
          <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono space-y-2">
            <div className="flex items-center space-x-2 font-bold text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
              <span>ThreatLens Extension Connected Successfully!</span>
            </div>
            <p className="text-[11px] text-slate-300">
              Your browser extension is now securely paired. You can close this tab or proceed to your dashboard.
            </p>
            <div className="pt-2">
              <button
                type="button"
                onClick={() => navigate('/scanner')}
                className="w-full py-2 px-3 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs font-mono transition-colors"
              >
                Continue to Dashboard &rarr;
              </button>
            </div>
          </div>
        )}

        <Alert type="error" message={error} onClose={() => setError('')} />

        {/* CASE 2: User is ALREADY authenticated during extension flow */}
        {user && isExtensionFlow && !extensionLinked && (
          <div className="space-y-4 pt-2">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-700/60 space-y-2">
              <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                <UserCheck className="w-4 h-4 text-cyan-400" />
                <span>Signed in as:</span>
                <span className="text-slate-200 font-semibold">{user.email || user.name}</span>
              </div>
            </div>

            {isLinkingExtension ? (
              <div className="flex items-center justify-center space-x-2 py-4 text-cyan-400 text-sm font-mono">
                <Loader2 className="w-5 h-5 animate-spin" />
                <span>Authorizing extension session...</span>
              </div>
            ) : error ? (
              <button
                type="button"
                onClick={() => {
                  handoffExecutedRef.current = false;
                  performExtensionHandoff();
                }}
                className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Retry Extension Authorization</span>
              </button>
            ) : null}

            <div className="text-center pt-2">
              <button
                type="button"
                onClick={async () => {
                  await logout();
                  handoffExecutedRef.current = false;
                }}
                className="text-xs text-slate-400 hover:text-slate-200 font-mono transition-colors"
              >
                Sign in with a different account
              </button>
            </div>
          </div>
        )}

        {/* CASE 1: User is NOT authenticated yet */}
        {!user && (!isExtensionFlow || !extensionLinked) && (
          <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1.5">
                  Email Address
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                    <Mail className="h-4 w-4 text-slate-400" />
                  </div>
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analyst@threatlens.io"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-mono uppercase tracking-wider text-slate-300 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                    <Lock className="h-4 w-4 text-slate-400" />
                  </div>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-700 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors font-mono"
                  />
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || isLinkingExtension}
              className="w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-all duration-200 shadow-md hover:shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isSubmitting || isLinkingExtension ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Authenticating...</span>
                </>
              ) : (
                <>
                  <span>{isExtensionFlow ? 'Sign In & Link Extension' : 'Sign In'}</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}

        {!user && (
          <div className="text-center pt-2">
            <p className="text-xs text-slate-400">
              Don't have an analyst account?{' '}
              <Link
                to="/register"
                className="text-cyan-400 hover:text-cyan-300 font-medium font-mono hover:underline"
              >
                Create Account
              </Link>
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

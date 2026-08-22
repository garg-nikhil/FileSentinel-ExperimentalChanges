import React, { useState } from 'react';
import { Shield, Lock, User, KeyRound, AlertCircle, ArrowRight, Check } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

export const LoginView: React.FC = () => {
  const { login } = useAuth();
  const [username, setUsername] = useState('devadmin');
  const [password, setPassword] = useState('devpassword');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;

    setError(null);
    setLoading(true);

    try {
      const res = await login(username.trim(), password.trim(), 'dev-device-default');
      if (!res.success) {
        setError(res.error || 'Invalid credentials');
      }
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickLogin = (user: string, pass: string) => {
    setUsername(user);
    setPassword(pass);
  };

  return (
    <div className="flex h-screen items-center justify-center bg-slate-950 text-slate-100 font-sans p-4">
      <div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        {/* Header */}
        <div className="p-8 border-b border-slate-800 text-center relative">
          <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 mx-auto mb-4 shadow-lg shadow-emerald-500/10">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold text-slate-100 tracking-tight">
            FileSentinel Enterprise
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Sign in to access your secure file workspace
          </p>
        </div>

        {/* Login Form */}
        <div className="p-8 space-y-6">
          {error && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-xl flex items-center gap-2.5 text-xs text-rose-300">
              <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                Username
              </label>
              <div className="relative flex items-center">
                <User className="w-4 h-4 text-slate-500 absolute left-3.5 pointer-events-none" />
                <input
                  id="input-login-username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. devadmin"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                  required
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                Password
              </label>
              <div className="relative flex items-center">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3.5 pointer-events-none" />
                <input
                  id="input-login-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                  required
                />
              </div>
            </div>

            <button
              id="btn-login-submit"
              type="submit"
              disabled={loading}
              className="w-full mt-2 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 text-white font-medium text-xs py-2.5 rounded-xl transition-all shadow-lg shadow-emerald-950/30 flex items-center justify-center gap-2 cursor-pointer"
            >
              {loading ? (
                <span>Authenticating...</span>
              ) : (
                <>
                  <span>Sign In</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Quick Dev Accounts */}
          <div className="border-t border-slate-800/80 pt-4 space-y-2">
            <div className="text-[11px] text-slate-500 font-mono uppercase tracking-wider text-center">
              Quick Dev Logins
            </div>
            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                id="btn-quick-login-user"
                onClick={() => handleQuickLogin('user', 'userpassword')}
                className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-slate-300 text-[11px] rounded-lg border border-slate-700/60 transition-colors text-center cursor-pointer"
              >
                User (<span className="text-emerald-400">user</span>)
              </button>
              <button
                type="button"
                id="btn-quick-login-org"
                onClick={() => handleQuickLogin('devadmin', 'devpassword')}
                className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-slate-300 text-[11px] rounded-lg border border-slate-700/60 transition-colors text-center cursor-pointer"
              >
                Org (<span className="text-cyan-400">devadmin</span>)
              </button>
              <button
                type="button"
                id="btn-quick-login-super"
                onClick={() => handleQuickLogin('sysadmin', 'SysAdmin123!')}
                className="px-2 py-1.5 bg-slate-800/60 hover:bg-slate-800 text-slate-300 text-[11px] rounded-lg border border-slate-700/60 transition-colors text-center cursor-pointer"
              >
                Super (<span className="text-rose-400">sysadmin</span>)
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

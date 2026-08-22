import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { UserLayout } from '../layouts/UserLayout';
import { OrgAdminLayout } from '../layouts/OrgAdminLayout';
import { SuperAdminLayout } from '../layouts/SuperAdminLayout';
import { LoginView } from './common/LoginView';
import { ClientClockMonitor } from '../services/clockMonitor';
import { api } from '../services/api';
import { ScanSession } from '../types';
import {
  AlertTriangle,
  RefreshCw,
  Download,
  Shield,
  ChevronDown,
  Check
} from 'lucide-react';

export const RoleRouter: React.FC = () => {
  const { user, authStatus, activeViewRole, canPreviewRoles, switchRoleView, isLoading } = useAuth();
  const [activeScan, setActiveScan] = useState<ScanSession | null>(null);
  const [recentScanId, setRecentScanId] = useState<string | null>(null);
  const [isScanLocked, setIsScanLocked] = useState<boolean>(false);
  const [lockReason, setLockReason] = useState<string>('');
  const [isRevalidating, setIsRevalidating] = useState<boolean>(false);
  const [revalidateError, setRevalidateError] = useState<string | null>(null);
  const [isDownloadingLogs, setIsDownloadingLogs] = useState<boolean>(false);
  const [autoRevalidate, setAutoRevalidate] = useState<boolean>(false);
  const [isRoleDropdownOpen, setIsRoleDropdownOpen] = useState<boolean>(false);
  const [switchFeedback, setSwitchFeedback] = useState<string | null>(null);

  // Auto-attempt revalidation every 60s if enabled
  useEffect(() => {
    if (!user || !isScanLocked || !autoRevalidate) return;

    const interval = setInterval(() => {
      handleRevalidate();
    }, 60000);

    return () => clearInterval(interval);
  }, [user, isScanLocked, autoRevalidate]);

  useEffect(() => {
    if (!user) return;

    // 1. Initial license rollback check
    const checkServerLicense = async () => {
      try {
        const status = await api.getOfflineLicenseStatus();
        if (status && (status.status === 'CLOCK_ROLLBACK_DETECTED' || status.clockRollbackDetected)) {
          setIsScanLocked(true);
          setLockReason('System clock tampering or rollback detected on backend. Scanning is blocked.');
        } else {
          localStorage.setItem('last_successful_sync', new Date().toISOString());
        }
      } catch (e) {
        console.error('[RoleRouter] License check error:', e);
      }
    };
    checkServerLicense();

    // 2. Client-side clock monitor
    const monitor = new ClientClockMonitor();
    monitor.start((reason) => {
      setIsScanLocked(true);
      setLockReason(reason);
    });

    return () => {
      monitor.stop();
    };
  }, [user?.userId]);

  const handleDownloadLogs = async () => {
    setIsDownloadingLogs(true);
    setRevalidateError(null);
    try {
      const logs = await api.getClockMonitorLogs();
      if (logs && logs.length > 0) {
        const headers = ['Log ID', 'Timestamp', 'Drift (ms)', 'Performance Time (ms)', 'Date Time (ms)', 'Status'];
        const csvRows = [headers.join(',')];
        for (const log of logs) {
          csvRows.push([
            log.id,
            log.timestamp,
            log.delta_ms,
            log.elapsed_performance_ms,
            log.elapsed_date_ms,
            log.status
          ].map(val => `"${val}"`).join(','));
        }
        const csvContent = csvRows.join('\n');
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.setAttribute('href', url);
        link.setAttribute('download', `forensic_clock_drift_logs_${new Date().toISOString().slice(0, 10)}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      } else {
        setRevalidateError('No forensic heartbeat logs found in database.');
      }
    } catch (err: any) {
      setRevalidateError(`Failed to export forensic logs: ${err.message}`);
    } finally {
      setIsDownloadingLogs(false);
    }
  };

  const handleRevalidate = async () => {
    setIsRevalidating(true);
    setRevalidateError(null);
    try {
      const response = await api.revalidateOfflineLicense();
      if (response.success && response.valid) {
        setIsScanLocked(false);
        setLockReason('');
        localStorage.setItem('last_successful_sync', new Date().toISOString());
      } else {
        setRevalidateError(response.error || 'Revalidation failed. Keep clock synchronized.');
      }
    } catch (err: any) {
      setRevalidateError(err.message || 'System clock is still out of sync.');
    } finally {
      setIsRevalidating(false);
    }
  };

  const handleScanComplete = (scanId: string) => {
    setRecentScanId(scanId);
  };

  const handleSwitchRole = async (targetRole: string) => {
    setIsRoleDropdownOpen(false);
    const res = await switchRoleView(targetRole);
    if (!res.success) {
      setSwitchFeedback(res.error || 'Unable to switch role view');
      setTimeout(() => setSwitchFeedback(null), 3000);
    }
  };

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-slate-900 text-slate-200">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 animate-pulse">
            <Shield className="w-6 h-6" />
          </div>
          <p className="text-xs font-mono text-slate-400">Initializing FileSentinel Workspace...</p>
        </div>
      </div>
    );
  }

  // If not authenticated, display LoginView
  if (!user) {
    return <LoginView />;
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden">
      {/* Top Role Switcher Bar - Available for Administrators or in Dev Mode */}
      {canPreviewRoles && (
        <header className={`h-10 px-4 flex items-center justify-between text-xs select-none shrink-0 z-40 transition-colors ${
          activeViewRole === 'USER'
            ? 'bg-white border-b border-slate-200 text-slate-700 shadow-2xs'
            : 'bg-slate-900 border-b border-slate-800 text-slate-200'
        }`}>
          <div className="flex items-center gap-3">
            <span className={`font-semibold flex items-center gap-1.5 ${
              activeViewRole === 'USER' ? 'text-slate-900' : 'text-slate-200'
            }`}>
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              FileSentinel
            </span>

            <span className={activeViewRole === 'USER' ? 'text-slate-300' : 'text-slate-600'}>|</span>

            <span className={`text-[11px] ${
              activeViewRole === 'USER' ? 'text-slate-500' : 'text-slate-400'
            }`}>
              Active Experience:
            </span>

            <div className="relative">
              <button
                id="btn-role-switcher"
                onClick={() => setIsRoleDropdownOpen(!isRoleDropdownOpen)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-bold font-mono uppercase flex items-center gap-1.5 border transition-all cursor-pointer ${
                  activeViewRole === 'SUPER_ADMIN'
                    ? 'bg-rose-500/20 text-rose-300 border-rose-500/40 hover:bg-rose-500/30'
                    : activeViewRole === 'ORG_ADMIN'
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 hover:bg-cyan-500/30'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100/70 shadow-2xs'
                }`}
              >
                {activeViewRole === 'SUPER_ADMIN' ? 'Super Admin (Ops)' : activeViewRole === 'ORG_ADMIN' ? 'Org Admin (Portal)' : 'User (Simple UI)'}
                <ChevronDown className="w-3 h-3" />
              </button>

              {isRoleDropdownOpen && (
                <div className={`absolute top-full left-0 mt-1 w-48 rounded-xl shadow-xl overflow-hidden py-1 z-50 animate-in fade-in zoom-in-95 duration-100 ${
                  activeViewRole === 'USER'
                    ? 'bg-white border border-slate-200 text-slate-800'
                    : 'bg-slate-900 border border-slate-700 text-slate-200'
                }`}>
                  <div className={`px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider border-b ${
                    activeViewRole === 'USER'
                      ? 'text-slate-400 border-slate-100 bg-slate-50'
                      : 'text-slate-400 border-slate-800 bg-slate-950'
                  }`}>
                    Switch Role View
                  </div>
                  <button
                    id="btn-switch-user"
                    onClick={() => handleSwitchRole('USER')}
                    className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between transition-colors cursor-pointer ${
                      activeViewRole === 'USER'
                        ? 'hover:bg-slate-50 hover:text-emerald-700 text-slate-700 font-medium'
                        : 'hover:bg-slate-800 hover:text-emerald-300 text-slate-200'
                    }`}
                  >
                    <span>1. User (Simple UI)</span>
                    {activeViewRole === 'USER' && <Check className="w-3.5 h-3.5 text-emerald-600" />}
                  </button>
                  <button
                    id="btn-switch-org-admin"
                    onClick={() => handleSwitchRole('ORG_ADMIN')}
                    className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between transition-colors cursor-pointer ${
                      activeViewRole === 'USER'
                        ? 'hover:bg-slate-50 hover:text-cyan-700 text-slate-700'
                        : 'hover:bg-slate-800 hover:text-cyan-300 text-slate-200'
                    }`}
                  >
                    <span>2. Org Admin (Portal)</span>
                    {activeViewRole === 'ORG_ADMIN' && <Check className="w-3.5 h-3.5 text-cyan-500" />}
                  </button>
                  <button
                    id="btn-switch-super-admin"
                    onClick={() => handleSwitchRole('SUPER_ADMIN')}
                    className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between transition-colors cursor-pointer ${
                      activeViewRole === 'USER'
                        ? 'hover:bg-slate-50 hover:text-rose-700 text-slate-700'
                        : 'hover:bg-slate-800 hover:text-rose-300 text-slate-200'
                    }`}
                  >
                    <span>3. Super Admin (Ops)</span>
                    {activeViewRole === 'SUPER_ADMIN' && <Check className="w-3.5 h-3.5 text-rose-500" />}
                  </button>
                </div>
              )}
            </div>

            {switchFeedback && (
              <span className={`text-xs font-medium px-2 py-0.5 rounded border animate-fade-in ${
                activeViewRole === 'USER'
                  ? 'bg-amber-50 text-amber-800 border-amber-200'
                  : 'bg-amber-950/40 text-amber-400 border-amber-500/20'
              }`}>
                {switchFeedback}
              </span>
            )}
          </div>

          <div className={`flex items-center gap-3 font-mono text-[11px] ${
            activeViewRole === 'USER' ? 'text-slate-500' : 'text-slate-400'
          }`}>
            <span>Org: <strong className={`font-sans ${activeViewRole === 'USER' ? 'text-slate-800' : 'text-slate-300'}`}>{user?.organizationName || 'Default'}</strong></span>
            <span>Real Role: <strong className={`font-sans ${activeViewRole === 'USER' ? 'text-slate-800' : 'text-slate-300'}`}>{user?.role || 'ORG_ADMIN'}</strong></span>
          </div>
        </header>
      )}

      {/* Clock Tampering / Rollback Warning Banner */}
      {isScanLocked && (
        <div className="bg-red-500/10 border-b border-red-500/20 px-6 py-3 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-red-200 shrink-0 bg-slate-900">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-0.5 bg-red-500/20 rounded text-red-400 font-bold font-mono text-xs uppercase tracking-wider">
                  Scan Locked
                </span>
                <p className="text-xs font-medium">{lockReason || 'System clock drift detected.'}</p>
              </div>
              {revalidateError && (
                <p className="text-xs text-red-400 mt-1 font-mono bg-red-950/40 px-2 py-0.5 rounded border border-red-500/10">
                  <span className="font-bold">Error:</span> {revalidateError}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleDownloadLogs}
              disabled={isDownloadingLogs}
              className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 border border-slate-700 cursor-pointer"
            >
              <Download className="w-3 h-3" />
              {isDownloadingLogs ? 'Exporting...' : 'Logs'}
            </button>
            <button
              onClick={handleRevalidate}
              disabled={isRevalidating}
              className="bg-red-600 hover:bg-red-500 text-white text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 border border-red-500/30 cursor-pointer"
            >
              <RefreshCw className={`w-3 h-3 ${isRevalidating ? 'animate-spin' : ''}`} />
              {isRevalidating ? 'Revalidating...' : 'Revalidate Clock'}
            </button>
          </div>
        </div>
      )}

      {/* Role-Based Layout Selection based on activeViewRole */}
      <div className="flex-1 overflow-hidden">
        {activeViewRole === 'SUPER_ADMIN' ? (
          <SuperAdminLayout
            isScanLocked={isScanLocked}
            activeScan={activeScan}
            setActiveScan={setActiveScan}
            onScanComplete={handleScanComplete}
            recentScanId={recentScanId}
          />
        ) : activeViewRole === 'ORG_ADMIN' ? (
          <OrgAdminLayout
            isScanLocked={isScanLocked}
            activeScan={activeScan}
            setActiveScan={setActiveScan}
            onScanComplete={handleScanComplete}
            recentScanId={recentScanId}
          />
        ) : (
          <UserLayout
            isScanLocked={isScanLocked}
            lockReason={lockReason}
            activeScan={activeScan}
            setActiveScan={setActiveScan}
            onScanComplete={handleScanComplete}
            recentScanId={recentScanId}
          />
        )}
      </div>
    </div>
  );
};

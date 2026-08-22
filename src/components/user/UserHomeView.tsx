import React, { useState, useEffect } from 'react';
import {
  Shield,
  FolderSearch,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCheck,
  History,
  ArrowRight,
  Info,
  Clock
} from 'lucide-react';
import { api } from '../../services/api';
import { DashboardStats, ScanSession } from '../../types';

import { getFileOutcomeSummary } from '../../services/canonicalSelectors';

interface UserHomeViewProps {
  onStartScan: () => void;
  onNavigateToCompliance: () => void;
  onNavigateToHistory: () => void;
  recentScanId?: string | null;
}

export const UserHomeView: React.FC<UserHomeViewProps> = ({
  onStartScan,
  onNavigateToCompliance,
  onNavigateToHistory
}) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<ScanSession[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    loadRealScanData();
  }, []);

  const loadRealScanData = async () => {
    setIsLoading(true);
    try {
      const [dashboardStats, scans] = await Promise.all([
        api.getDashboardStats().catch(() => null),
        api.getScanHistory().catch(() => [])
      ]);
      setStats(dashboardStats);
      setRecentScans(scans || []);
    } catch (err) {
      console.error('[UserHomeView] Error loading real scan data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const latestScan = recentScans.length > 0 ? recentScans[0] : null;
  const fileSummary = stats?.fileSummary || getFileOutcomeSummary(latestScan);

  // Derive counts directly from canonical summary (Guarantees Total = Passed + Failed + Review)
  const totalScanned = fileSummary.total_scanned;
  const passedCount = fileSummary.passed;
  const failedCount = fileSummary.failed;
  const reviewCount = fileSummary.review;

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      {/* 1. Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
            <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <Shield className="w-5 h-5" />
            </span>
            FileSentinel
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Protect your files before they leave your organization.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onNavigateToHistory}
            className="px-3.5 py-2 text-xs font-medium text-slate-600 hover:text-slate-900 bg-white hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors shadow-2xs cursor-pointer flex items-center gap-1.5"
          >
            <History className="w-3.5 h-3.5 text-slate-400" />
            Scan History
          </button>
          <button
            id="btn-user-start-scan-home"
            onClick={onStartScan}
            className="px-4 py-2 text-xs font-semibold text-white bg-emerald-600 hover:bg-emerald-500 rounded-lg transition-colors shadow-xs cursor-pointer flex items-center gap-1.5"
          >
            <FolderSearch className="w-4 h-4" />
            Start Scan
          </button>
        </div>
      </div>

      {/* 2. Primary Scan CTA Card */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
        <div className="space-y-2 max-w-xl">
          <h2 className="text-lg font-bold text-slate-900">
            Run File Inspection & DLP Compliance
          </h2>
          <p className="text-xs text-slate-500 leading-relaxed">
            Scan your local documents, spreadsheets, PDFs, and code repositories to detect sensitive personal information, credentials, and compliance violations with zero data leakage.
          </p>
          <div className="flex items-center gap-2 text-[11px] text-slate-400 font-medium pt-1">
            <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            All scans execute 100% locally on your computer.
          </div>
        </div>

        <button
          onClick={onStartScan}
          className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white text-xs font-semibold rounded-xl transition-all shadow-md shadow-emerald-600/10 flex items-center justify-center gap-2 shrink-0 cursor-pointer"
        >
          <FolderSearch className="w-4 h-4" />
          START SCAN NOW
        </button>
      </div>

      {/* 3. Real Backend Scan Results Summary */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 sm:p-8 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-4">
          <div>
            <h2 className="text-base font-bold text-slate-900">
              Recent Scan Summary
            </h2>
            <p className="text-xs text-slate-500">
              {isLoading ? (
                'Loading scan metrics from backend...'
              ) : totalScanned > 0 ? (
                `${totalScanned.toLocaleString()} total files evaluated`
              ) : (
                'No scans recorded yet'
              )}
            </p>
          </div>

          <button
            onClick={onNavigateToCompliance}
            className="px-3.5 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-medium rounded-lg border border-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer self-start sm:self-center shadow-2xs"
          >
            <FileCheck className="w-3.5 h-3.5 text-emerald-600" />
            View Full Audit & Compliance
            <ArrowRight className="w-3 h-3 text-slate-400" />
          </button>
        </div>

        {/* Real 3-Outcome Metrics Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Passed */}
          <div
            onClick={onNavigateToCompliance}
            className="bg-slate-50/70 hover:bg-slate-50 border border-slate-200 hover:border-emerald-300 p-5 rounded-xl transition-all cursor-pointer space-y-2 group shadow-2xs"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-emerald-700 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                Passed
              </span>
              <span className="text-[11px] text-slate-400 font-normal group-hover:text-slate-600">Safe</span>
            </div>
            <div className="text-3xl font-bold text-slate-900 font-mono">
              {passedCount.toLocaleString()}
            </div>
            <p className="text-xs text-slate-500">
              Clean files with zero policy violations
            </p>
          </div>

          {/* Failed */}
          <div
            onClick={onNavigateToCompliance}
            className="bg-slate-50/70 hover:bg-slate-50 border border-slate-200 hover:border-rose-300 p-5 rounded-xl transition-all cursor-pointer space-y-2 group shadow-2xs"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-rose-700 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <XCircle className="w-4 h-4 text-rose-600" />
                Failed
              </span>
              <span className="text-[11px] text-rose-600 font-semibold">Action Needed</span>
            </div>
            <div className="text-3xl font-bold text-rose-600 font-mono">
              {failedCount.toLocaleString()}
            </div>
            <p className="text-xs text-slate-500">
              PII or prohibited findings detected
            </p>
          </div>

          {/* Review */}
          <div
            onClick={onNavigateToCompliance}
            className="bg-slate-50/70 hover:bg-slate-50 border border-slate-200 hover:border-amber-300 p-5 rounded-xl transition-all cursor-pointer space-y-2 group shadow-2xs"
          >
            <div className="flex items-center justify-between text-xs font-semibold text-amber-700 uppercase tracking-wider">
              <span className="flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                Review
              </span>
              <span className="text-[11px] text-amber-600 font-semibold">Ambiguous</span>
            </div>
            <div className="text-3xl font-bold text-amber-600 font-mono">
              {reviewCount.toLocaleString()}
            </div>
            <p className="text-xs text-slate-500">
              Requires human confirmation
            </p>
          </div>
        </div>

        {/* Latest Scan Session Details */}
        {latestScan && (
          <div className="pt-2 border-t border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-500">
            <div className="flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              <span>
                Last Scan: <strong className="text-slate-700 font-sans">{latestScan.root_path}</strong> ({new Date(latestScan.start_time).toLocaleString()})
              </span>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 uppercase self-start sm:self-center">
              {latestScan.status}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

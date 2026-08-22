import React, { useState, useEffect } from 'react';
import {
  FileCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Search,
  Filter,
  ArrowRight,
  Shield,
  FileText,
  AlertCircle,
  X,
  Clock,
  Check,
  ChevronRight,
  HelpCircle,
  Info,
  FolderSearch
} from 'lucide-react';
import { api } from '../../services/api';
import {
  getFileOutcomeSummary,
  getChecklistSummary,
  getFindingsSummary,
  CanonicalChecklistSummary
} from '../../services/canonicalSelectors';
import { FileItem, ScanSession } from '../../types';

interface UserAuditViewProps {
  recentScanId?: string | null;
}

export const UserAuditView: React.FC<UserAuditViewProps> = ({ recentScanId }) => {
  const [sessions, setSessions] = useState<any[]>([]);
  const [activeSession, setActiveSession] = useState<any | null>(null);
  const [linkedScan, setLinkedScan] = useState<ScanSession | null>(null);
  const [scanFiles, setScanFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'PASS' | 'FAIL' | 'REVIEW'>('ALL');
  const [selectedItem, setSelectedItem] = useState<any | null>(null);

  useEffect(() => {
    loadAuditData();
  }, [recentScanId]);

  const loadAuditData = async () => {
    setLoading(true);
    try {
      // 1. Fetch audit sessions
      let list = await api.getAuditSessions().catch(() => []);
      if (!Array.isArray(list)) list = [];

      let sessionToLoad = null;

      // If recentScanId provided and existing audit found for it, fetch detail
      if (recentScanId && list.length > 0) {
        const match = list.find((s: any) => s.scan_id === recentScanId);
        if (match) {
          sessionToLoad = await api.getAuditSessionDetail(match.audit_id).catch(() => match);
        }
      }

      // If recentScanId provided and no existing audit, run audit for scan
      if (!sessionToLoad && recentScanId) {
        try {
          const newAudit = await api.runAuditScan({
            scan_id: recentScanId,
            audit_date: new Date().toISOString().split('T')[0],
            agency_name: 'Workstation Compliance Inspector',
            auditor_name: 'Automated Compliance Engine'
          });
          if (newAudit && newAudit.audit_id) {
            sessionToLoad = await api.getAuditSessionDetail(newAudit.audit_id).catch(() => newAudit);
            list = [sessionToLoad, ...list];
          }
        } catch {
          // Fallback
        }
      }

      if (!sessionToLoad && list.length > 0) {
        sessionToLoad = await api.getAuditSessionDetail(list[0].audit_id).catch(() => list[0]);
      }

      setSessions(list);
      setActiveSession(sessionToLoad);

      // Load associated scan session files if available
      const targetScanId = sessionToLoad?.scan_id || recentScanId;
      if (targetScanId) {
        const [scanProgress, files] = await Promise.all([
          api.getScanProgress(targetScanId).catch(() => null),
          api.getScanFiles(targetScanId).catch(() => [])
        ]);
        setLinkedScan(scanProgress);
        setScanFiles(files || []);
      }
    } catch (err) {
      console.error('[UserAuditView] Error loading audit data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSession = async (auditId: string) => {
    setLoading(true);
    try {
      const detail = await api.getAuditSessionDetail(auditId);
      setActiveSession(detail);
      if (detail?.scan_id) {
        const [scanProgress, files] = await Promise.all([
          api.getScanProgress(detail.scan_id).catch(() => null),
          api.getScanFiles(detail.scan_id).catch(() => [])
        ]);
        setLinkedScan(scanProgress);
        setScanFiles(files || []);
      }
    } catch (err) {
      console.error('[UserAuditView] Error fetching session detail:', err);
    } finally {
      setLoading(false);
    }
  };

  // Canonical checklist summary (29 parameters)
  const checklistSummary: CanonicalChecklistSummary = getChecklistSummary(activeSession);
  
  // Canonical file outcome summary (e.g. 39 files: 32 pass, 7 fail, 0 review)
  const fileSummary = getFileOutcomeSummary(linkedScan, scanFiles);
  const findingsSummary = getFindingsSummary(scanFiles, linkedScan);

  // Extract and filter checklist parameters
  const parameters: any[] = activeSession?.parameter_results || activeSession?.parameters || [];
  const filteredParameters = parameters.filter(param => {
    const status = param.override ? param.override.new_status : param.status;
    const matchesStatus = statusFilter === 'ALL' || status === statusFilter;
    const name = param.parameter?.name || param.parameter_id || '';
    const category = param.parameter?.category || '';
    const matchesSearch =
      searchQuery === '' ||
      name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      category.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesStatus && matchesSearch;
  });

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      {/* 1. Header */}
      <div className="border-b border-slate-200 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
            <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <FileCheck className="w-5 h-5" />
            </span>
            Audit & Compliance
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Review the results of your latest file inspection and compliance evaluations.
          </p>
        </div>

        {sessions.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500 font-medium">Session:</span>
            <select
              value={activeSession?.audit_id || ''}
              onChange={(e) => handleSelectSession(e.target.value)}
              className="bg-white border border-slate-200 text-slate-800 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 shadow-2xs"
            >
              {sessions.map((s, idx) => (
                <option key={s.audit_id || idx} value={s.audit_id}>
                  {new Date(s.created_at || s.timestamp || Date.now()).toLocaleDateString()} — {s.audit_id}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {loading ? (
        <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center text-slate-400 text-xs font-mono animate-pulse">
          Loading audit inspection results...
        </div>
      ) : !activeSession ? (
        <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center space-y-3">
          <FileCheck className="w-10 h-10 text-slate-300 mx-auto" />
          <h3 className="text-sm font-bold text-slate-800">No Audit Records Available</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Run a file scan first to automatically generate a comprehensive audit and compliance report.
          </p>
        </div>
      ) : (
        <>
          {/* LEVEL 1: FILE SCAN SUMMARY (Part 3 & 7) */}
          {fileSummary.total_discovered > 0 && (
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                    <FolderSearch className="w-4 h-4 text-emerald-600" />
                    File Scan Summary
                  </h3>
                  <p className="text-xs text-slate-500 mt-0.5">
                    File-level outcome classification across all {fileSummary.total_scanned} scanned documents.
                  </p>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  Scan Session: {activeSession?.scan_id || 'CURRENT'}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 pt-1">
                <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
                  <div className="text-xs font-semibold text-slate-600">Total Scanned</div>
                  <div className="text-2xl font-bold text-slate-900 font-mono">{fileSummary.total_scanned}</div>
                  <p className="text-[11px] text-slate-400">{fileSummary.total_discovered} files discovered</p>
                </div>

                <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
                  <div className="text-xs font-semibold text-emerald-700 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" /> Files Passed
                  </div>
                  <div className="text-2xl font-bold text-emerald-700 font-mono">{fileSummary.passed}</div>
                  <p className="text-[11px] text-slate-400">{fileSummary.passed_pct}% clean documents</p>
                </div>

                <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
                  <div className="text-xs font-semibold text-rose-700 flex items-center gap-1.5">
                    <XCircle className="w-4 h-4 text-rose-600" /> Files Failed
                  </div>
                  <div className="text-2xl font-bold text-rose-600 font-mono">{fileSummary.failed}</div>
                  <p className="text-[11px] text-slate-400">{fileSummary.failed_pct}% with violations</p>
                </div>

                <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
                  <div className="text-xs font-semibold text-amber-700 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-600" /> Needs Review
                  </div>
                  <div className="text-2xl font-bold text-amber-600 font-mono">{fileSummary.review}</div>
                  <p className="text-[11px] text-slate-400">{fileSummary.review_pct}% ambiguous files</p>
                </div>
              </div>
            </div>
          )}

          {/* LEVEL 3: CHECKLIST COMPLIANCE SUMMARY (Part 3 & 7: 29 Parameters evaluated) */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-900">
              Checklist Compliance Summary (29 Parameters)
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              {/* Compliance Status */}
              <div className="bg-white border border-slate-200 p-5 rounded-2xl shadow-xs space-y-2">
                <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
                  Overall Audit Status
                </span>
                <div className="flex items-baseline gap-2">
                  <span className="text-xl font-bold text-slate-900 font-mono">
                    {checklistSummary.overall_status}
                  </span>
                </div>
                <p className="text-xs text-slate-500">
                  {checklistSummary.total_parameters} regulatory parameters evaluated
                </p>
              </div>

              {/* Passed Parameters */}
              <div
                onClick={() => setStatusFilter('PASS')}
                className={`bg-white border p-5 rounded-2xl shadow-xs space-y-2 cursor-pointer transition-all ${
                  statusFilter === 'PASS' ? 'border-emerald-500 ring-2 ring-emerald-500/10' : 'border-slate-200 hover:border-emerald-300'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold text-emerald-700 uppercase tracking-wider">
                  <span className="flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                    Parameters Passed
                  </span>
                  <span className="text-[11px] text-slate-400 font-normal">Compliant</span>
                </div>
                <div className="text-3xl font-bold text-slate-900 font-mono">
                  {checklistSummary.passed}
                </div>
                <p className="text-xs text-slate-500">Satisfies policy rules</p>
              </div>

              {/* Failed Parameters */}
              <div
                onClick={() => setStatusFilter('FAIL')}
                className={`bg-white border p-5 rounded-2xl shadow-xs space-y-2 cursor-pointer transition-all ${
                  statusFilter === 'FAIL' ? 'border-rose-500 ring-2 ring-rose-500/10' : 'border-slate-200 hover:border-rose-300'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold text-rose-700 uppercase tracking-wider">
                  <span className="flex items-center gap-1.5">
                    <XCircle className="w-4 h-4 text-rose-600" />
                    Parameters Failed
                  </span>
                  <span className="text-[11px] text-rose-600 font-semibold">Violation</span>
                </div>
                <div className="text-3xl font-bold text-rose-600 font-mono">
                  {checklistSummary.failed}
                </div>
                <p className="text-xs text-slate-500">Requires policy action</p>
              </div>

              {/* Review Parameters */}
              <div
                onClick={() => setStatusFilter('REVIEW')}
                className={`bg-white border p-5 rounded-2xl shadow-xs space-y-2 cursor-pointer transition-all ${
                  statusFilter === 'REVIEW' ? 'border-amber-500 ring-2 ring-amber-500/10' : 'border-slate-200 hover:border-amber-300'
                }`}
              >
                <div className="flex items-center justify-between text-xs font-semibold text-amber-700 uppercase tracking-wider">
                  <span className="flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-600" />
                    Under Review
                  </span>
                  <span className="text-[11px] text-amber-600 font-semibold">Ambiguous</span>
                </div>
                <div className="text-3xl font-bold text-amber-600 font-mono">
                  {checklistSummary.review + checklistSummary.not_found}
                </div>
                <p className="text-xs text-slate-500">Evidence missing or in review</p>
              </div>
            </div>
          </div>

          {/* 3. Filter Toolbar & Parameters Table */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              {/* Search */}
              <div className="relative flex-1 max-w-md">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Search compliance parameters..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all"
                />
              </div>

              {/* Status Filter Badges */}
              <div className="flex items-center gap-1.5 flex-wrap">
                {(['ALL', 'FAIL', 'REVIEW', 'PASS'] as const).map(st => (
                  <button
                    key={st}
                    onClick={() => setStatusFilter(st)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-lg border transition-all cursor-pointer ${
                      statusFilter === st
                        ? 'bg-emerald-50 text-emerald-800 border-emerald-200 font-semibold shadow-2xs'
                        : 'bg-white text-slate-600 border-slate-200 hover:bg-slate-50'
                    }`}
                  >
                    {st === 'ALL' ? 'All Parameters' : st === 'FAIL' ? 'Failed' : st === 'REVIEW' ? 'Review' : 'Passed'}
                  </button>
                ))}
              </div>
            </div>

            {/* 4. Parameters Table */}
            <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
              <table className="w-full text-left text-xs border-collapse">
                <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                  <tr>
                    <th className="py-3 px-4">Parameter Check</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 bg-white">
                  {filteredParameters.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-slate-400 italic">
                        No compliance parameters matching the selected filter.
                      </td>
                    </tr>
                  ) : (
                    filteredParameters.map((p, idx) => {
                      const status = p.override ? p.override.new_status : p.status;
                      const paramName = p.parameter?.name || p.parameter_id;
                      const category = p.parameter?.category || 'Security Baseline';

                      return (
                        <tr key={p.parameter_id || idx} className="hover:bg-slate-50/70 transition-colors">
                          <td className="py-3 px-4">
                            <div className="font-semibold text-slate-900">{paramName}</div>
                            <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                              {p.parameter_id}
                            </div>
                          </td>
                          <td className="py-3 px-4 text-slate-600">
                            <span className="px-2 py-0.5 bg-slate-100 text-slate-700 rounded text-[11px] border border-slate-200/60">
                              {category}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            {status === 'PASS' ? (
                              <span className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-lg text-xs font-semibold inline-flex items-center gap-1.5">
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                                PASSED
                              </span>
                            ) : status === 'FAIL' ? (
                              <span className="px-2.5 py-1 bg-rose-50 text-rose-700 border border-rose-200 rounded-lg text-xs font-semibold inline-flex items-center gap-1.5">
                                <XCircle className="w-3.5 h-3.5 text-rose-600" />
                                FAILED
                              </span>
                            ) : (
                              <span className="px-2.5 py-1 bg-amber-50 text-amber-700 border border-amber-200 rounded-lg text-xs font-semibold inline-flex items-center gap-1.5">
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                                REVIEW
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <button
                              onClick={() => setSelectedItem(p)}
                              className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 hover:text-slate-900 font-medium text-xs rounded-lg border border-slate-200 transition-colors cursor-pointer shadow-2xs inline-flex items-center gap-1"
                            >
                              Details
                              <ChevronRight className="w-3 h-3 text-slate-400" />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* 5. Detail Modal for Checklist Parameter */}
      {selectedItem && (
        <div className="fixed inset-0 bg-slate-950/40 backdrop-blur-xs flex items-center justify-center p-4 z-50 animate-in fade-in duration-150">
          <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-lg w-full p-6 space-y-5 animate-in zoom-in-95 duration-150">
            {/* Modal Header */}
            <div className="flex items-start justify-between gap-4 border-b border-slate-100 pb-4">
              <div className="space-y-1">
                <span className="text-[10px] font-mono uppercase text-slate-400">
                  {selectedItem.parameter_id}
                </span>
                <h3 className="text-base font-bold text-slate-900">
                  {selectedItem.parameter?.name || selectedItem.parameter_id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedItem(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Status & Category */}
            <div className="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-200/80 text-xs">
              <span className="text-slate-500 font-medium">Evaluation Status:</span>
              <div>
                {(selectedItem.override ? selectedItem.override.new_status : selectedItem.status) === 'PASS' ? (
                  <span className="px-2.5 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-md font-semibold inline-flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3 text-emerald-600" /> PASSED
                  </span>
                ) : (selectedItem.override ? selectedItem.override.new_status : selectedItem.status) === 'FAIL' ? (
                  <span className="px-2.5 py-0.5 bg-rose-50 text-rose-700 border border-rose-200 rounded-md font-semibold inline-flex items-center gap-1">
                    <XCircle className="w-3 h-3 text-rose-600" /> FAILED
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 bg-amber-50 text-amber-700 border border-amber-200 rounded-md font-semibold inline-flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3 text-amber-600" /> REVIEW
                  </span>
                )}
              </div>
            </div>

            {/* Explanation & Remediation */}
            <div className="space-y-3 text-xs">
              <div>
                <h4 className="font-semibold text-slate-800 mb-1">Finding Summary</h4>
                <p className="text-slate-600 leading-relaxed bg-slate-50 p-3 rounded-xl border border-slate-200/60">
                  {selectedItem.reason ||
                    selectedItem.evidence?.summary ||
                    'Inspection confirmed this parameter aligns with your organization compliance rules.'}
                </p>
              </div>

              <div>
                <h4 className="font-semibold text-slate-800 mb-1">Recommended Action</h4>
                <p className="text-slate-600 leading-relaxed bg-emerald-50/50 text-emerald-900 p-3 rounded-xl border border-emerald-200/60">
                  {selectedItem.remediation ||
                    'No remediation required. The tested files and configurations satisfy security guidelines.'}
                </p>
              </div>
            </div>

            {/* Close */}
            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setSelectedItem(null)}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-semibold rounded-xl transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

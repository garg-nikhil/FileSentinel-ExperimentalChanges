import React, { useState, useEffect } from 'react';
import {
  History,
  Clock,
  Folder,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  FileCheck,
  Search,
  Filter
} from 'lucide-react';
import { api } from '../../services/api';
import { ScanSession } from '../../types';

interface UserHistoryViewProps {
  onNavigateToCompliance?: (scanId?: string) => void;
}

export const UserHistoryView: React.FC<UserHistoryViewProps> = ({ onNavigateToCompliance }) => {
  const [scans, setScans] = useState<ScanSession[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');

  useEffect(() => {
    loadScanHistory();
  }, []);

  const loadScanHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getScanHistory();
      setScans(data || []);
    } catch (err) {
      console.error('[UserHistoryView] Error loading scan history:', err);
    } finally {
      setLoading(false);
    }
  };

  const filteredScans = scans.filter(s => {
    if (!searchQuery.trim()) return true;
    const target = s.root_path || '';
    const id = s.scan_id || '';
    return target.toLowerCase().includes(searchQuery.toLowerCase()) || id.toLowerCase().includes(searchQuery.toLowerCase());
  });

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      {/* 1. Header */}
      <div className="border-b border-slate-200 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
            <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <History className="w-5 h-5" />
            </span>
            Scan History
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Review previous file scans, inspection outcomes, and audit records.
          </p>
        </div>

        {/* Search */}
        <div className="relative max-w-xs w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            placeholder="Search past scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-white border border-slate-200 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 shadow-2xs transition-all"
          />
        </div>
      </div>

      {/* 2. Scans History Table */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-400 text-xs font-mono animate-pulse">
            Loading past scan sessions...
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <Clock className="w-10 h-10 text-slate-300 mx-auto" />
            <h3 className="text-sm font-bold text-slate-800">No Past Scans Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              You haven&apos;t run any file scans yet. Go to &quot;Scan Files&quot; to inspect your documents.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                <tr>
                  <th className="py-3 px-4">Target Folder</th>
                  <th className="py-3 px-4">Date & Time</th>
                  <th className="py-3 px-4">Total Files</th>
                  <th className="py-3 px-4">Passed</th>
                  <th className="py-3 px-4">Failed</th>
                  <th className="py-3 px-4">Review</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {filteredScans.map((s, idx) => {
                  const passed = s.safe_count || 0;
                  const failed = (s.critical_count || 0) + (s.high_count || 0);
                  const review = (s.medium_count || 0) + (s.low_count || 0);

                  return (
                    <tr key={s.scan_id || idx} className="hover:bg-slate-50/70 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-900 flex items-center gap-2">
                          <Folder className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                          <span className="truncate max-w-xs">{s.root_path}</span>
                        </div>
                        <span className="text-[10px] text-slate-400 font-mono block mt-0.5">
                          {s.scan_id}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-600 font-mono text-[11px]">
                        {new Date(s.start_time).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono font-bold text-slate-800">
                        {s.total_files.toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono text-emerald-700 font-semibold">
                        {passed.toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono text-rose-600 font-semibold">
                        {failed.toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono text-amber-600 font-semibold">
                        {review.toLocaleString()}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border uppercase ${
                          s.status === 'COMPLETED'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : s.status === 'SCANNING'
                            ? 'bg-blue-50 text-blue-700 border-blue-200'
                            : 'bg-slate-100 text-slate-700 border-slate-200'
                        }`}>
                          {s.status}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        {onNavigateToCompliance && (
                          <button
                            onClick={() => onNavigateToCompliance(s.scan_id)}
                            className="px-3 py-1.5 bg-slate-50 hover:bg-slate-100 text-slate-700 hover:text-slate-900 font-medium text-xs rounded-lg border border-slate-200 transition-colors cursor-pointer shadow-2xs inline-flex items-center gap-1"
                          >
                            <FileCheck className="w-3 h-3 text-emerald-600" />
                            Audit View
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

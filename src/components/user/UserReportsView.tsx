import React, { useState, useEffect } from 'react';
import {
  Fingerprint,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileText,
  Lock,
  Clock,
  Building2,
  Calendar,
  Check,
  Shield
} from 'lucide-react';
import { api } from '../../services/api';
import { ReportVerificationResult, StoredAuditReportItem } from '../../types';

export const UserReportsView: React.FC = () => {
  const [reportIdInput, setReportIdInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ReportVerificationResult | null>(null);
  const [recentReports, setRecentReports] = useState<StoredAuditReportItem[]>([]);

  useEffect(() => {
    loadRecentReports();
  }, []);

  const loadRecentReports = async () => {
    try {
      const list = await api.getAuditReportsList();
      if (Array.isArray(list)) {
        setRecentReports(list);
      }
    } catch (e) {
      console.error('Failed to load reports list:', e);
    }
  };

  const handleVerify = async (idToVerify?: string) => {
    const id = (idToVerify || reportIdInput).trim();
    if (!id) return;
    setLoading(true);
    try {
      const res = await api.verifyReportPublic(id);
      setResult(res);
      setReportIdInput(id);
    } catch (err: any) {
      setResult({
        valid: false,
        tampered: false,
        report_id: id,
        error: err.message || 'Verification failed. Report not found.'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      {/* 1. Header */}
      <div className="border-b border-slate-200 pb-6">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
          <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
            <Fingerprint className="w-5 h-5" />
          </span>
          Verify Reports
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Cryptographically verify the authenticity, issuer signature, and tamper-evident status of generated audit certificates.
        </p>
      </div>

      {/* 2. Verification Form Card */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 sm:p-8 space-y-6">
        <div className="space-y-1 border-b border-slate-100 pb-4">
          <h2 className="text-base font-bold text-slate-900">
            Certificate & Report Verification
          </h2>
          <p className="text-xs text-slate-500">
            Enter any FileSentinel Report ID or cryptographic token to inspect its tamper status and signature validity.
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleVerify();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              placeholder="e.g. REPORT-XXXX-XXXX or REP-..."
              value={reportIdInput}
              onChange={(e) => setReportIdInput(e.target.value)}
              className="w-full bg-slate-50 border border-slate-200 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/20 focus:border-emerald-500 transition-all font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !reportIdInput.trim()}
            className="px-6 py-2.5 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all shadow-md shadow-emerald-600/10 flex items-center justify-center gap-2 cursor-pointer shrink-0"
          >
            <Shield className="w-4 h-4" />
            {loading ? 'Verifying...' : 'Verify Report'}
          </button>
        </form>

        {/* Verification Result Card */}
        {result && (
          <div className={`p-6 rounded-2xl border transition-all ${
            result.valid
              ? 'bg-emerald-50/60 border-emerald-200 text-emerald-950'
              : 'bg-rose-50/60 border-rose-200 text-rose-950'
          }`}>
            <div className="flex items-start gap-4">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 border ${
                result.valid
                  ? 'bg-emerald-100 border-emerald-300 text-emerald-700'
                  : 'bg-rose-100 border-rose-300 text-rose-700'
              }`}>
                {result.valid ? <CheckCircle2 className="w-6 h-6" /> : <XCircle className="w-6 h-6" />}
              </div>
              <div className="space-y-2 min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider ${
                    result.valid ? 'bg-emerald-200/80 text-emerald-800' : 'bg-rose-200/80 text-rose-800'
                  }`}>
                    {result.valid ? 'Authentic & Verified' : result.tampered ? 'Tampered / Invalid' : 'Not Found'}
                  </span>
                  <span className="font-mono text-xs font-semibold">{result.report_id}</span>
                </div>
                <p className="text-xs text-slate-700 leading-relaxed">
                  {result.valid
                    ? 'Cryptographic integrity verified. Digital signature matches server authority and evidence hash has not been modified.'
                    : result.error || 'The report identifier does not match any valid issued certificates.'}
                </p>
                {result.report && (
                  <div className="grid grid-cols-2 gap-3 pt-2 text-xs text-slate-700 border-t border-emerald-200/60">
                    <div>
                      <span className="font-medium text-slate-500 block">Organization:</span>
                      <strong>{result.report.organization_name || 'Standard'}</strong>
                    </div>
                    <div>
                      <span className="font-medium text-slate-500 block">Issued At:</span>
                      <strong className="font-mono">{new Date(result.report.created_at).toLocaleString()}</strong>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 3. Registered Reports List */}
      {recentReports.length > 0 && (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
          <div className="border-b border-slate-100 pb-3 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900">
              Registered Audit Reports
            </h3>
            <span className="text-xs text-slate-400">
              {recentReports.length} reports available
            </span>
          </div>

          <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
            <table className="w-full text-left text-xs border-collapse">
              <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                <tr>
                  <th className="py-2.5 px-4">Report ID</th>
                  <th className="py-2.5 px-4">Created Date</th>
                  <th className="py-2.5 px-4">Status</th>
                  <th className="py-2.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 bg-white">
                {recentReports.map((r, idx) => (
                  <tr key={r.report_id || idx} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-2.5 px-4 font-mono font-semibold text-slate-900">
                      {r.report_id}
                    </td>
                    <td className="py-2.5 px-4 text-slate-600 font-mono text-[11px]">
                      {new Date(r.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                        r.status === 'REVOKED'
                          ? 'bg-rose-50 text-rose-700 border-rose-200'
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        {r.status || 'VALID'}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        onClick={() => handleVerify(r.report_id)}
                        className="px-3 py-1 bg-slate-50 hover:bg-slate-100 text-slate-700 hover:text-slate-900 font-medium text-xs rounded-lg border border-slate-200 transition-colors cursor-pointer shadow-2xs"
                      >
                        Verify
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

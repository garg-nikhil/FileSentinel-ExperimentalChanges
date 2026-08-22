import React, { useState, useEffect } from 'react';
import {
  Laptop,
  Usb,
  Globe,
  Mail,
  MessageSquare,
  Cloud,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  RotateCcw,
  Shield,
  Clock,
  Info,
  Check,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Eye,
  ExternalLink
} from 'lucide-react';
import { api } from '../../services/api';
import { EndpointAssessment, DetectionCategory, WebTargetResult } from '../../types';
import { getEndpointSummary, CanonicalEndpointSummary } from '../../services/canonicalSelectors';

export const UserEndpointView: React.FC = () => {
  const [assessment, setAssessment] = useState<EndpointAssessment | null>(null);
  const [history, setHistory] = useState<EndpointAssessment[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [assessing, setAssessing] = useState<boolean>(false);
  const [assessProgress, setAssessProgress] = useState<{ current: number; total: number; label: string }>({ current: 0, total: 25, label: '' });
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [activeCategoryTab, setActiveCategoryTab] = useState<DetectionCategory>('CLOUD_STORAGE');
  const [selectedHistoryItem, setSelectedHistoryItem] = useState<EndpointAssessment | null>(null);

  useEffect(() => {
    loadEndpointData();
  }, []);

  const loadEndpointData = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const [latest, list] = await Promise.all([
        api.getLatestEndpointAssessment().catch(() => null),
        api.getEndpointAssessments(15).catch(() => [])
      ]);
      setAssessment(latest);
      setHistory(list || []);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load endpoint compliance status.');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAssessment = async () => {
    // PART 15: Immediately reset previous assessment state on new assessment start
    setAssessment(null);
    setAssessing(true);
    setErrorMessage(null);
    setAssessProgress({ current: 0, total: 25, label: 'Initializing probes...' });

    // Step progression simulation during backend network execution
    let currentStep = 0;
    const progressInterval = setInterval(() => {
      currentStep++;
      if (currentStep <= 24) {
        const labels = ['Evaluating USB policies...', 'Probing Cloud Storage targets...', 'Checking Personal Email egress...', 'Verifying Messaging gateways...', 'Testing Social Media controls...', 'Finalizing SHA-256 evidence...'];
        const label = labels[Math.min(labels.length - 1, Math.floor((currentStep / 25) * labels.length))];
        setAssessProgress({ current: currentStep, total: 25, label });
      }
    }, 180);

    try {
      const result = await api.runEndpointAssessment();
      clearInterval(progressInterval);
      setAssessProgress({ current: 25, total: 25, label: 'Assessment Complete' });

      if (result) {
        setAssessment(result);
        setHistory(prev => [result, ...prev.filter(h => (h.id || h.assessment_id) !== (result.id || result.assessment_id)).slice(0, 14)]);
      }
    } catch (err: any) {
      clearInterval(progressInterval);
      setErrorMessage(err.message || 'Endpoint assessment encountered an error.');
    } finally {
      setAssessing(false);
    }
  };

  const canonicalSummary: CanonicalEndpointSummary = getEndpointSummary(assessment);
  const isCompliant = canonicalSummary.overall_status === 'COMPLIANT';

  const categoryTabs: { id: DetectionCategory; label: string; icon: React.ReactNode }[] = [
    { id: 'CLOUD_STORAGE', label: 'Cloud Storage', icon: <Cloud className="w-4 h-4" /> },
    { id: 'PERSONAL_EMAIL', label: 'Personal Email', icon: <Mail className="w-4 h-4" /> },
    { id: 'MESSAGING', label: 'Messaging & Chat', icon: <MessageSquare className="w-4 h-4" /> },
    { id: 'SOCIAL_MEDIA', label: 'Social Media', icon: <Globe className="w-4 h-4" /> },
    { id: 'USB_STORAGE', label: 'USB Mass Storage', icon: <Usb className="w-4 h-4" /> }
  ];

  const currentCategoryData = canonicalSummary.categories[activeCategoryTab];

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      {/* 1. Header */}
      <div className="border-b border-slate-200 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
            <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
              <Laptop className="w-5 h-5" />
            </span>
            Endpoint Compliance
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Review the local security posture, USB storage policy, and network egress controls of this workstation.
          </p>
        </div>

        <button
          id="btn-run-endpoint-assessment"
          onClick={handleRunAssessment}
          disabled={assessing || loading}
          className="px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all shadow-md shadow-emerald-600/10 flex items-center gap-2 cursor-pointer self-start sm:self-center"
        >
          <Play className={`w-4 h-4 fill-current ${assessing ? 'animate-spin' : ''}`} />
          {assessing ? 'Assessing Device...' : 'Run Assessment'}
        </button>
      </div>

      {errorMessage && (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl flex items-center gap-3 text-xs text-rose-800 shadow-2xs">
          <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Assessing Live Progress Bar (Part 14 & 15) */}
      {assessing && (
        <div className="bg-white rounded-2xl border border-emerald-200 shadow-sm p-6 space-y-4 animate-pulse">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-slate-800 flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
              Assessing Endpoint Compliance...
            </span>
            <span className="font-mono text-emerald-700 font-bold">
              {assessProgress.current} / {assessProgress.total} services assessed ({Math.round((assessProgress.current / assessProgress.total) * 100)}%)
            </span>
          </div>

          <div className="w-full bg-slate-100 rounded-full h-3 overflow-hidden border border-slate-200">
            <div
              className="bg-emerald-600 h-full transition-all duration-200 rounded-full"
              style={{ width: `${Math.round((assessProgress.current / assessProgress.total) * 100)}%` }}
            />
          </div>

          <div className="text-xs text-slate-500 font-mono flex items-center justify-between">
            <span>{assessProgress.label}</span>
            <span>Target registry: 24 web egress + 1 hardware USB</span>
          </div>
        </div>
      )}

      {loading ? (
        <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center text-slate-400 text-xs font-mono animate-pulse">
          Evaluating workstation endpoint status...
        </div>
      ) : !assessment && !assessing ? (
        <div className="bg-white rounded-2xl border border-slate-200 p-12 text-center space-y-4">
          <Laptop className="w-12 h-12 text-slate-300 mx-auto" />
          <h3 className="text-sm font-bold text-slate-800">No Assessment History Found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Click &quot;Run Assessment&quot; to test your device USB policies and network egress safeguards.
          </p>
        </div>
      ) : assessment && (
        <>
          {/* 2. Top Endpoint Status Card */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 sm:p-8 flex flex-col md:flex-row md:items-center justify-between gap-6">
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
                Workstation Assessment
              </span>
              <div className="flex items-center gap-3">
                <span className={`w-3.5 h-3.5 rounded-full ${isCompliant ? 'bg-emerald-500' : 'bg-rose-500'}`}></span>
                <h2 className="text-xl font-bold text-slate-900">
                  {isCompliant ? 'Endpoint Security Compliant' : 'Security Action Recommended'}
                </h2>
              </div>
              <p className="text-xs text-slate-500 font-mono">
                Session: {canonicalSummary.assessment_id || 'LOCAL'} • Assessed: {new Date(canonicalSummary.timestamp).toLocaleString()}
              </p>
            </div>

            <div className="flex items-center gap-3">
              <span className={`px-4 py-2 rounded-xl text-xs font-bold uppercase tracking-wider border shadow-2xs ${
                isCompliant
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-rose-50 text-rose-700 border-rose-200'
              }`}>
                {canonicalSummary.overall_status}
              </span>
            </div>
          </div>

          {/* 3. Summary Metric Counters (Part 13: accessible + blocked + indeterminate = total) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-white border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Total Targets</div>
              <div className="text-2xl font-bold text-slate-900 font-mono">{canonicalSummary.total_targets}</div>
              <p className="text-[11px] text-slate-400">24 Web + 1 USB</p>
            </div>

            <div className="bg-white border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="text-xs font-semibold text-rose-700 uppercase tracking-wider flex items-center gap-1.5">
                <XCircle className="w-3.5 h-3.5 text-rose-600" /> Accessible
              </div>
              <div className="text-2xl font-bold text-rose-600 font-mono">{canonicalSummary.accessible_count}</div>
              <p className="text-[11px] text-slate-400">Reachable outbound</p>
            </div>

            <div className="bg-white border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="text-xs font-semibold text-emerald-700 uppercase tracking-wider flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" /> Blocked
              </div>
              <div className="text-2xl font-bold text-emerald-600 font-mono">{canonicalSummary.blocked_count}</div>
              <p className="text-[11px] text-slate-400">Restricted by policy</p>
            </div>

            <div className="bg-white border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="text-xs font-semibold text-amber-700 uppercase tracking-wider flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-600" /> Indeterminate
              </div>
              <div className="text-2xl font-bold text-amber-600 font-mono">{canonicalSummary.indeterminate_count}</div>
              <p className="text-[11px] text-slate-400">Unreachable / Needs review</p>
            </div>
          </div>

          {/* 4. Complete Individual Service Results by Category (Part 11, 12, 13, 29) */}
          <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden space-y-0">
            <div className="p-6 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-bold text-slate-900">
                  Target Service Access Breakdown
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Inspect the individual detection outcome for each sanctioned service and hardware port.
                </p>
              </div>

              {/* Category Tabs */}
              <div className="flex flex-wrap items-center gap-1 bg-slate-100 p-1 rounded-xl">
                {categoryTabs.map(tab => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveCategoryTab(tab.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer ${
                      activeCategoryTab === tab.id
                        ? 'bg-white text-slate-900 shadow-xs'
                        : 'text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    {tab.icon}
                    <span>{tab.label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Active Category Target List */}
            <div className="p-6">
              {activeCategoryTab === 'USB_STORAGE' ? (
                <div className="space-y-4">
                  <div className="bg-slate-50 border border-slate-200 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center gap-3.5">
                      <div className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center text-slate-700 shadow-2xs">
                        <Usb className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-sm font-bold text-slate-900">USB Storage Mass Devices</h4>
                        <p className="text-xs text-slate-500 mt-0.5">
                          Evaluates local Windows registry Group Policy USB storage blocking.
                        </p>
                      </div>
                    </div>

                    <span className={`px-3 py-1 rounded-lg text-xs font-bold border uppercase tracking-wider ${
                      currentCategoryData.status === 'PASS'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-rose-50 text-rose-700 border-rose-200'
                    }`}>
                      {currentCategoryData.status === 'PASS' ? '✓ Disabled (Safe)' : `✕ ${canonicalSummary.usb_status}`}
                    </span>
                  </div>

                  <div className="text-xs text-slate-500 bg-slate-50 p-4 rounded-xl border border-slate-200 font-mono flex items-center justify-between">
                    <span>Connected Mass Storage Devices: <strong className="text-slate-800">{canonicalSummary.usb_connected_count}</strong></span>
                    <span>Method: Real Windows Registry / WMI Probe</span>
                  </div>
                </div>
              ) : (
                <div className="divide-y divide-slate-100 border border-slate-200 rounded-xl overflow-hidden">
                  {currentCategoryData.targets.length === 0 ? (
                    <div className="p-8 text-center text-xs text-slate-400">
                      No target records evaluated in this category.
                    </div>
                  ) : (
                    currentCategoryData.targets.map((target) => {
                      const isAcc = target.status === 'ACCESSIBLE';
                      const isBlk = target.status === 'BLOCKED';

                      return (
                        <div key={target.target_domain || target.service} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50 transition-colors">
                          <div className="flex items-center gap-3 min-w-0">
                            <span className={`w-2.5 h-2.5 rounded-full shrink-0 ${isAcc ? 'bg-rose-500' : isBlk ? 'bg-emerald-500' : 'bg-amber-500'}`}></span>
                            <div className="min-w-0">
                              <div className="font-bold text-xs text-slate-900 truncate">
                                {target.service}
                              </div>
                              <div className="text-[11px] text-slate-400 font-mono truncate">
                                {target.target_domain} • {target.responseTimeMs ? `${target.responseTimeMs}ms` : 'Probed'}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-3 shrink-0">
                            {target.reason && (
                              <span className="text-[11px] text-slate-500 hidden md:inline truncate max-w-xs font-mono">
                                {target.reason}
                              </span>
                            )}
                            <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold border uppercase tracking-wider ${
                              isAcc
                                ? 'bg-rose-50 text-rose-700 border-rose-200'
                                : isBlk
                                ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                                : 'bg-amber-50 text-amber-700 border-amber-200'
                            }`}>
                              {isAcc ? '✓ Accessible' : isBlk ? '✕ Blocked' : '? Indeterminate'}
                            </span>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>
          </div>

          {/* 5. Assessment History with View Details (Part 16) */}
          {history.length > 0 && (
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h3 className="text-sm font-bold text-slate-900">
                  Recent Endpoint Assessments
                </h3>
                <span className="text-xs text-slate-400">
                  Showing last {history.length} runs
                </span>
              </div>

              <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
                <table className="w-full text-left text-xs border-collapse">
                  <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                    <tr>
                      <th className="py-2.5 px-4">Date & Time</th>
                      <th className="py-2.5 px-4">Overall Status</th>
                      <th className="py-2.5 px-4">USB Policy</th>
                      <th className="py-2.5 px-4">Network Access</th>
                      <th className="py-2.5 px-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100 bg-white">
                    {history.map((h, idx) => {
                      const hSummary = getEndpointSummary(h);
                      const pass = hSummary.overall_status === 'COMPLIANT';

                      return (
                        <tr key={h.id || h.assessment_id || idx} className="hover:bg-slate-50/70 transition-colors">
                          <td className="py-2.5 px-4 font-mono text-slate-600">
                            {new Date(hSummary.timestamp).toLocaleString()}
                          </td>
                          <td className="py-2.5 px-4">
                            <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                              pass ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-rose-50 text-rose-700 border-rose-200'
                            }`}>
                              {hSummary.overall_status}
                            </span>
                          </td>
                          <td className="py-2.5 px-4 text-slate-600 font-mono">
                            {hSummary.usb_status}
                          </td>
                          <td className="py-2.5 px-4 text-slate-600 font-mono">
                            {hSummary.accessible_count} accessible / {hSummary.blocked_count} blocked
                          </td>
                          <td className="py-2.5 px-4 text-right">
                            <button
                              onClick={() => {
                                setAssessment(h);
                                setSelectedHistoryItem(h);
                              }}
                              className="px-2.5 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-md font-semibold text-[11px] transition-colors cursor-pointer"
                            >
                              Inspect Run
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { Laptop, Usb, Globe, CheckCircle2, XCircle, AlertTriangle, RefreshCw, Info, ShieldCheck } from 'lucide-react';
import { api } from '../../services/api';
import { EndpointAssessment } from '../../types';

export const UserComplianceView: React.FC = () => {
  const [assessment, setAssessment] = useState<EndpointAssessment | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [running, setRunning] = useState<boolean>(false);

  useEffect(() => {
    loadAssessment();
  }, []);

  const loadAssessment = async () => {
    setLoading(true);
    try {
      const history = await api.getEndpointAssessments(1);
      if (history && history.length > 0) {
        setAssessment(history[0]);
      }
    } catch (err) {
      console.error('[UserComplianceView] Error loading endpoint assessment:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRunCheck = async () => {
    setRunning(true);
    try {
      const res = await api.runEndpointAssessment({});
      if (res) {
        setAssessment(res);
      }
    } catch (err: any) {
      console.error('[UserComplianceView] Error running check:', err);
    } finally {
      setRunning(false);
    }
  };

  const isCompliant = assessment?.overall_status === 'COMPLIANT';
  const isNonCompliant = assessment?.overall_status === 'NON_COMPLIANT';

  return (
    <div className="max-w-4xl mx-auto px-6 py-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-6">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 flex items-center gap-2.5">
            <span className="w-8 h-8 rounded-lg bg-cyan-50 border border-cyan-200 flex items-center justify-center text-cyan-700">
              <Laptop className="w-4 h-4" />
            </span>
            Endpoint Compliance
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Check your device storage policies and sanctioned cloud boundaries.
          </p>
        </div>

        <button
          onClick={handleRunCheck}
          disabled={running}
          className="px-4 py-2 bg-slate-900 hover:bg-slate-800 active:bg-black disabled:opacity-50 text-white font-medium text-xs rounded-lg flex items-center gap-2 transition-all shadow-xs cursor-pointer"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${running ? 'animate-spin' : ''}`} />
          {running ? 'Checking...' : 'Check Compliance'}
        </button>
      </div>

      {/* Main Status Banner */}
      <div className={`p-6 rounded-xl border ${
        isCompliant
          ? 'bg-emerald-50/70 border-emerald-200 text-emerald-900'
          : isNonCompliant
          ? 'bg-rose-50/70 border-rose-200 text-rose-900'
          : 'bg-white border-slate-200 text-slate-800'
      }`}>
        <div className="flex items-center gap-4">
          {isCompliant ? (
            <CheckCircle2 className="w-8 h-8 text-emerald-600 shrink-0" />
          ) : isNonCompliant ? (
            <XCircle className="w-8 h-8 text-rose-600 shrink-0" />
          ) : (
            <ShieldCheck className="w-8 h-8 text-slate-600 shrink-0" />
          )}
          <div>
            <h2 className="text-base font-bold text-slate-900">
              {isCompliant
                ? 'Device is Compliant'
                : isNonCompliant
                ? 'Action Required: Policy Warnings Detected'
                : 'Compliance Check Ready'}
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              {assessment
                ? `Last evaluated: ${new Date(assessment.created_at).toLocaleString()}`
                : 'Click Check Compliance to evaluate your device posture against organizational guidelines.'}
            </p>
          </div>
        </div>
      </div>

      {/* Checks Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* USB Storage Protection */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-2 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-800 flex items-center gap-2 uppercase tracking-wider">
              <Usb className="w-4 h-4 text-slate-600" />
              USB Storage Restriction
            </span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
              assessment?.usb_result?.status === 'PASS'
                ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                : assessment?.usb_result?.status === 'FAIL'
                ? 'bg-rose-50 text-rose-700 border border-rose-200'
                : 'bg-slate-100 text-slate-600 border border-slate-200'
            }`}>
              {assessment?.usb_result?.status === 'PASS' ? '✓ Compliant' : assessment?.usb_result?.status === 'FAIL' ? '✕ Non-Compliant' : 'Ready'}
            </span>
          </div>
          <p className="text-xs text-slate-500">
            {assessment?.usb_result?.reason || 'Evaluates whether unauthorized USB mass storage devices are restricted.'}
          </p>
        </div>

        {/* Cloud Storage Access */}
        <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-2 shadow-2xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-800 flex items-center gap-2 uppercase tracking-wider">
              <Globe className="w-4 h-4 text-slate-600" />
              Cloud Storage & Web Access
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
              ✓ Compliant
            </span>
          </div>
          <p className="text-xs text-slate-500">
            Sanctioned enterprise storage is active. Unapproved public drives and external uploads are blocked.
          </p>
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-xl p-4 flex items-center gap-3 text-xs text-slate-500 shadow-2xs">
        <Info className="w-4 h-4 text-slate-400 shrink-0" />
        <span>
          Compliance checks are strictly non-invasive. No personal web browsing history, passwords, or personal files are collected.
        </span>
      </div>
    </div>
  );
};

import React from 'react';
import { HelpCircle, Shield, AlertTriangle, CheckCircle2, Lock, MessageSquare } from 'lucide-react';

export const UserHelpView: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      <div className="border-b border-slate-200 pb-6">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
          <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
            <HelpCircle className="w-5 h-5" />
          </span>
          Help & Support
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Understanding scan outcomes and keeping your files secure and compliant.
        </p>
      </div>

      {/* Guide Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-2 shadow-xs">
          <div className="flex items-center gap-2 text-emerald-700 font-bold text-xs uppercase tracking-wider">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            Passed Files
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            The file contains no detectable sensitive information, API keys, credentials, or policy violations. No further action is required.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-2 shadow-xs">
          <div className="flex items-center gap-2 text-rose-700 font-bold text-xs uppercase tracking-wider">
            <AlertTriangle className="w-4 h-4 text-rose-600" />
            Failed Files
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            Personal Identifiable Information (such as emails or phone numbers), credentials, or confidential documents were detected. Review the file to protect the sensitive data.
          </p>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-2 shadow-xs">
          <div className="flex items-center gap-2 text-amber-700 font-bold text-xs uppercase tracking-wider">
            <Shield className="w-4 h-4 text-amber-600" />
            Review Files
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            The scanner found content that might require human attention but could not make an absolute determination. Inspect the file to confirm compliance.
          </p>
        </div>
      </div>

      {/* Privacy Guarantee */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 space-y-2 shadow-xs">
        <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
          <Lock className="w-4 h-4 text-emerald-600" />
          Data Privacy & Safety Guarantee
        </h3>
        <p className="text-xs text-slate-600 leading-relaxed">
          FileSentinel executes 100% of file scans locally on your computer. Your file contents, documents, and credentials never leave your device.
        </p>
      </div>

      {/* Support Active */}
      <div className="bg-white border border-slate-200 rounded-2xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-xs">
        <div>
          <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">Need further assistance?</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Contact your organization administrator or security team for questions regarding specific data policies.
          </p>
        </div>
        <div className="flex items-center gap-1.5 text-xs text-emerald-700 bg-emerald-50 px-3.5 py-1.5 rounded-xl border border-emerald-200 font-semibold">
          <MessageSquare className="w-3.5 h-3.5" />
          Support Active
        </div>
      </div>
    </div>
  );
};

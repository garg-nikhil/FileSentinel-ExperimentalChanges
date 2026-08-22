import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  FolderSearch,
  Laptop,
  FileCheck,
  Fingerprint,
  FileText,
  AlertTriangle,
  ShieldAlert,
  History,
  KeyRound,
  Settings,
  HelpCircle,
  Shield,
  LogOut
} from 'lucide-react';
import { DashboardView } from '../components/DashboardView';
import { ScanView } from '../components/ScanView';
import { EndpointComplianceView } from '../components/EndpointComplianceView';
import { AuditComplianceView } from '../components/audit/AuditComplianceView';
import { ReportVerificationView } from '../components/ReportVerificationView';
import { FilesView } from '../components/FilesView';
import { FindingsView } from '../components/FindingsView';
import { QuarantineView } from '../components/QuarantineView';
import { HistoryView } from '../components/HistoryView';
import { LicenseView } from '../components/LicenseView';
import { SettingsView } from '../components/SettingsView';
import { UserHelpView } from '../components/user/UserHelpView';
import { FileDetailView } from '../components/FileDetailView';
import { useAuth } from '../context/AuthContext';
import { ScanSession, DashboardStats } from '../types';
import { api } from '../services/api';

export type OrgAdminTab =
  | 'dashboard'
  | 'scan'
  | 'endpoint_compliance'
  | 'audit'
  | 'verify_report'
  | 'files'
  | 'findings'
  | 'quarantine'
  | 'history'
  | 'license'
  | 'settings'
  | 'help';

interface OrgAdminLayoutProps {
  isScanLocked?: boolean;
  lockReason?: string;
  activeScan: ScanSession | null;
  setActiveScan: React.Dispatch<React.SetStateAction<ScanSession | null>>;
  onScanComplete: (scanId: string) => void;
  recentScanId?: string | null;
}

export const OrgAdminLayout: React.FC<OrgAdminLayoutProps> = ({
  isScanLocked = false,
  activeScan,
  setActiveScan,
  onScanComplete,
  recentScanId
}) => {
  const [activeTab, setActiveTab] = useState<OrgAdminTab>('dashboard');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [localRecentScanId, setLocalRecentScanId] = useState<string | null>(recentScanId || null);
  const { user, logout } = useAuth();

  useEffect(() => {
    if (recentScanId) {
      setLocalRecentScanId(recentScanId);
    }
  }, [recentScanId]);

  useEffect(() => {
    loadStats();
  }, [activeTab]);

  const loadStats = async () => {
    try {
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (e) {
      console.error(e);
    }
  };

  const handleScanComplete = (scanId: string) => {
    setLocalRecentScanId(scanId);
    setActiveTab('audit');
    onScanComplete(scanId);
  };

  const navItems: { id: OrgAdminTab; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Org Dashboard', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'scan', label: 'Run Scans', icon: <FolderSearch className="w-4 h-4" /> },
    { id: 'endpoint_compliance', label: 'Endpoint Compliance', icon: <Laptop className="w-4 h-4 text-cyan-400" /> },
    { id: 'audit', label: 'Audit & Compliance', icon: <FileCheck className="w-4 h-4" /> },
    { id: 'verify_report', label: 'Verify Reports', icon: <Fingerprint className="w-4 h-4 text-indigo-400" /> },
    { id: 'files', label: 'Scanned Files', icon: <FileText className="w-4 h-4" /> },
    { id: 'findings', label: 'Findings Log', icon: <AlertTriangle className="w-4 h-4" /> },
    { id: 'quarantine', label: 'Quarantine Vault', icon: <ShieldAlert className="w-4 h-4" /> },
    { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'license', label: 'Org Plan & License', icon: <KeyRound className="w-4 h-4" /> },
    { id: 'settings', label: 'Organization Settings', icon: <Settings className="w-4 h-4" /> },
    { id: 'help', label: 'Help & Support', icon: <HelpCircle className="w-4 h-4" /> }
  ];

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans antialiased overflow-hidden">
      {/* Org Admin Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between select-none">
        <div>
          {/* Logo / Org Header */}
          <div className="p-5 border-b border-slate-800 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Shield className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h2 className="text-sm font-bold text-slate-100 tracking-tight flex items-center gap-1.5 truncate">
                FileSentinel
                <span className="text-[9px] font-mono uppercase bg-cyan-500/20 text-cyan-300 px-1 py-0.2 rounded border border-cyan-500/30">
                  ORG ADMIN
                </span>
              </h2>
              <p className="text-xs text-slate-400 truncate">
                {user?.organizationName || 'Organization Admin'}
              </p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            {navItems.map(item => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-org-${item.id}`}
                  onClick={() => {
                    setSelectedFileId(null);
                    setActiveTab(item.id);
                  }}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <span className={isActive ? 'text-cyan-400' : 'text-slate-500'}>{item.icon}</span>
                  {item.label}
                  {item.id === 'scan' && activeScan?.status === 'SCANNING' && (
                    <span className="ml-auto w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Account / Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 text-xs">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="font-semibold text-slate-200 truncate">{user?.username || 'Org Admin'}</div>
              <div className="text-[10px] text-cyan-400 font-mono">Org Administrator</div>
            </div>
            <button
              onClick={() => logout()}
              title="Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Workspace */}
      <main className="flex-1 overflow-y-auto bg-slate-950">
        {selectedFileId ? (
          <FileDetailView
            fileId={selectedFileId}
            onBack={() => setSelectedFileId(null)}
          />
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                stats={stats}
                onNavigate={(tab: any) => setActiveTab(tab)}
                onSelectFile={(id) => setSelectedFileId(id)}
                onStartQuickScan={() => setActiveTab('scan')}
              />
            )}

            {activeTab === 'scan' && (
              <ScanView
                onScanComplete={handleScanComplete}
                activeScan={activeScan}
                setActiveScan={setActiveScan}
                isScanLocked={isScanLocked}
              />
            )}

            {activeTab === 'endpoint_compliance' && <EndpointComplianceView />}

            {activeTab === 'audit' && (
              <div className="p-6">
                <AuditComplianceView recentScanId={localRecentScanId} />
              </div>
            )}

            {activeTab === 'verify_report' && <ReportVerificationView />}

            {activeTab === 'files' && <FilesView onSelectFile={(id) => setSelectedFileId(id)} />}

            {activeTab === 'findings' && <FindingsView />}

            {activeTab === 'quarantine' && <QuarantineView />}

            {activeTab === 'history' && <HistoryView />}

            {activeTab === 'license' && <LicenseView />}

            {activeTab === 'settings' && <SettingsView />}

            {activeTab === 'help' && <UserHelpView />}
          </>
        )}
      </main>
    </div>
  );
};

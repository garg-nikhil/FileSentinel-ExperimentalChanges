import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  FolderSearch,
  Laptop,
  History,
  FileCheck,
  SlidersHorizontal,
  AlertTriangle,
  ShieldAlert,
  Fingerprint,
  FileText,
  ShieldCheck,
  KeyRound,
  Cloud,
  Settings,
  Shield,
  LogOut,
  Bell,
  Activity
} from 'lucide-react';
import { DashboardView } from '../components/DashboardView';
import { ScanView } from '../components/ScanView';
import { FilesView } from '../components/FilesView';
import { FileDetailView } from '../components/FileDetailView';
import { FindingsView } from '../components/FindingsView';
import { QuarantineView } from '../components/QuarantineView';
import { RulesView } from '../components/RulesView';
import { HistoryView } from '../components/HistoryView';
import { SettingsView } from '../components/SettingsView';
import { LicenseView } from '../components/LicenseView';
import { AuditComplianceView } from '../components/audit/AuditComplianceView';
import { VendorCloudDashboardView } from '../components/VendorCloudDashboardView';
import { EndpointComplianceView } from '../components/EndpointComplianceView';
import { ReportVerificationView } from '../components/ReportVerificationView';
import { AdminConsoleView } from '../components/AdminConsoleView';
import { useAuth } from '../context/AuthContext';
import { DashboardStats, ScanSession } from '../types';
import { api } from '../services/api';
import { useToast } from '../context/ToastContext';

export type SuperAdminTab =
  | 'dashboard'
  | 'scan'
  | 'endpoint_compliance'
  | 'history'
  | 'audit'
  | 'rules'
  | 'findings'
  | 'quarantine'
  | 'verify_report'
  | 'files'
  | 'admin_console'
  | 'license'
  | 'cloud_dashboard'
  | 'settings';

interface SuperAdminLayoutProps {
  isScanLocked?: boolean;
  activeScan: ScanSession | null;
  setActiveScan: React.Dispatch<React.SetStateAction<ScanSession | null>>;
  onScanComplete: (scanId: string) => void;
  recentScanId: string | null;
}

export const SuperAdminLayout: React.FC<SuperAdminLayoutProps> = ({
  isScanLocked = false,
  activeScan,
  setActiveScan,
  onScanComplete,
  recentScanId
}) => {
  const [activeTab, setActiveTab] = useState<SuperAdminTab>('dashboard');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [localRecentScanId, setLocalRecentScanId] = useState<string | null>(recentScanId || null);
  const { user, logout } = useAuth();
  const { unreadCount, setIsTrayOpen } = useToast();

  useEffect(() => {
    if (recentScanId) setLocalRecentScanId(recentScanId);
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

  const categories: {
    title: string;
    items: { id: SuperAdminTab; label: string; icon: React.ReactNode }[];
  }[] = [
    {
      title: 'OPERATIONS',
      items: [
        { id: 'dashboard', label: 'Local DLP Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
        { id: 'scan', label: 'Scanner Engine', icon: <FolderSearch className="w-4 h-4" /> },
        { id: 'endpoint_compliance', label: 'Endpoint Compliance', icon: <Laptop className="w-4 h-4 text-cyan-400" /> },
        { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> }
      ]
    },
    {
      title: 'SECURITY & RULES',
      items: [
        { id: 'audit', label: 'Audit Compliance', icon: <FileCheck className="w-4 h-4" /> },
        { id: 'rules', label: 'Rule Engine', icon: <SlidersHorizontal className="w-4 h-4" /> },
        { id: 'findings', label: 'Findings Log', icon: <AlertTriangle className="w-4 h-4" /> },
        { id: 'quarantine', label: 'Quarantine Vault', icon: <ShieldAlert className="w-4 h-4" /> },
        { id: 'verify_report', label: 'Report Verification', icon: <Fingerprint className="w-4 h-4 text-indigo-400" /> },
        { id: 'files', label: 'Scanned Files', icon: <FileText className="w-4 h-4" /> }
      ]
    },
    {
      title: 'ADMINISTRATION',
      items: [
        { id: 'admin_console', label: 'Admin & Pilot Console', icon: <ShieldCheck className="w-4 h-4 text-rose-400" /> },
        { id: 'license', label: 'Licensing & Plans', icon: <KeyRound className="w-4 h-4" /> }
      ]
    },
    {
      title: 'OBSERVABILITY & SYSTEM',
      items: [
        { id: 'cloud_dashboard', label: 'Vendor Cloud & Telemetry', icon: <Cloud className="w-4 h-4 text-emerald-400" /> },
        { id: 'settings', label: 'System Settings', icon: <Settings className="w-4 h-4" /> }
      ]
    }
  ];

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 font-sans antialiased overflow-hidden">
      {/* Super Admin Sidebar */}
      <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between select-none">
        <div className="overflow-y-auto">
          {/* Logo / Header */}
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-bold text-slate-100 tracking-tight flex items-center gap-1.5">
                  FileSentinel
                  <span className="text-[9px] font-mono uppercase bg-rose-500/20 text-rose-300 px-1 py-0.2 rounded border border-rose-500/30">
                    SUPER ADMIN
                  </span>
                </h2>
                <p className="text-[10px] text-slate-400 font-mono">Operations Console</p>
              </div>
            </div>

            <button
              onClick={() => setIsTrayOpen(true)}
              title="Security Alerts"
              className="relative p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-slate-700"
            >
              <Bell className="w-3.5 h-3.5 text-emerald-400" />
              {unreadCount > 0 && (
                <span className="absolute -top-1 -right-1 bg-rose-600 text-white font-mono text-[8px] font-bold w-3.5 h-3.5 rounded-full flex items-center justify-center">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>
          </div>

          {/* Categorized Navigation */}
          <nav className="p-3 space-y-4">
            {categories.map((cat, catIdx) => (
              <div key={catIdx} className="space-y-1">
                <div className="px-3 text-[10px] font-bold tracking-wider text-slate-500 uppercase font-mono">
                  {cat.title}
                </div>
                {cat.items.map(item => {
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      key={item.id}
                      id={`nav-super-${item.id}`}
                      onClick={() => {
                        setSelectedFileId(null);
                        setActiveTab(item.id);
                      }}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                        isActive
                          ? 'bg-rose-500/10 text-rose-300 border border-rose-500/20 font-semibold shadow-sm'
                          : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                      }`}
                    >
                      <span className={isActive ? 'text-rose-400' : 'text-slate-500'}>{item.icon}</span>
                      <span className="truncate">{item.label}</span>
                      {item.id === 'scan' && activeScan?.status === 'SCANNING' && (
                        <span className="ml-auto w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
        </div>

        {/* Super Admin Account / Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950/50 text-xs">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="font-semibold text-slate-200 truncate">{user?.username || 'Super Admin'}</div>
              <div className="text-[10px] text-rose-400 font-mono flex items-center gap-1">
                <Activity className="w-3 h-3" />
                Root System Access
              </div>
            </div>
            <button
              onClick={() => logout()}
              title="Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
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

            {activeTab === 'history' && <HistoryView />}

            {activeTab === 'audit' && (
              <div className="p-6">
                <AuditComplianceView recentScanId={localRecentScanId} />
              </div>
            )}

            {activeTab === 'rules' && <RulesView />}

            {activeTab === 'findings' && <FindingsView />}

            {activeTab === 'quarantine' && <QuarantineView />}

            {activeTab === 'verify_report' && <ReportVerificationView />}

            {activeTab === 'files' && <FilesView onSelectFile={(id) => setSelectedFileId(id)} />}

            {activeTab === 'admin_console' && <AdminConsoleView />}

            {activeTab === 'license' && <LicenseView />}

            {activeTab === 'cloud_dashboard' && <VendorCloudDashboardView />}

            {activeTab === 'settings' && <SettingsView />}
          </>
        )}
      </main>
    </div>
  );
};

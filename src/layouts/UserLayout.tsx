import React, { useState, useEffect } from 'react';
import {
  LayoutDashboard,
  FolderSearch,
  FileCheck,
  Laptop,
  History,
  Fingerprint,
  HelpCircle,
  Shield,
  LogOut
} from 'lucide-react';
import { UserHomeView } from '../components/user/UserHomeView';
import { UserScanView } from '../components/user/UserScanView';
import { UserAuditView } from '../components/user/UserAuditView';
import { UserEndpointView } from '../components/user/UserEndpointView';
import { UserHistoryView } from '../components/user/UserHistoryView';
import { UserReportsView } from '../components/user/UserReportsView';
import { UserHelpView } from '../components/user/UserHelpView';
import { FileDetailView } from '../components/FileDetailView';
import { useAuth } from '../context/AuthContext';
import { ScanSession } from '../types';

export type UserTab = 'home' | 'scan' | 'compliance' | 'endpoint_compliance' | 'history' | 'reports' | 'help';

interface UserLayoutProps {
  isScanLocked?: boolean;
  lockReason?: string;
  activeScan: ScanSession | null;
  setActiveScan: React.Dispatch<React.SetStateAction<ScanSession | null>>;
  onScanComplete: (scanId: string) => void;
  recentScanId?: string | null;
}

export const UserLayout: React.FC<UserLayoutProps> = ({
  isScanLocked = false,
  activeScan,
  setActiveScan,
  onScanComplete,
  recentScanId
}) => {
  const [activeTab, setActiveTab] = useState<UserTab>('home');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [localRecentScanId, setLocalRecentScanId] = useState<string | null>(recentScanId || null);
  const { user, logout } = useAuth();

  useEffect(() => {
    if (recentScanId) {
      setLocalRecentScanId(recentScanId);
    }
  }, [recentScanId]);

  const handleScanComplete = (scanId: string) => {
    setLocalRecentScanId(scanId);
    setActiveTab('compliance');
    onScanComplete(scanId);
  };

  const navItems: { id: UserTab; label: string; icon: React.ReactNode }[] = [
    { id: 'home', label: 'Home Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { id: 'scan', label: 'Scan Files', icon: <FolderSearch className="w-4 h-4" /> },
    { id: 'compliance', label: 'Audit & Compliance', icon: <FileCheck className="w-4 h-4" /> },
    { id: 'endpoint_compliance', label: 'Endpoint Compliance', icon: <Laptop className="w-4 h-4" /> },
    { id: 'history', label: 'Scan History', icon: <History className="w-4 h-4" /> },
    { id: 'reports', label: 'Verify Reports', icon: <Fingerprint className="w-4 h-4" /> },
    { id: 'help', label: 'Help & Support', icon: <HelpCircle className="w-4 h-4" /> }
  ];

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900 font-sans antialiased overflow-hidden">
      {/* Minimal Clean White Sidebar */}
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between select-none shadow-xs shrink-0">
        <div>
          {/* Logo / Brand Header */}
          <div className="p-5 border-b border-slate-100 flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600 shadow-2xs">
              <Shield className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <h2 className="text-sm font-bold text-slate-900 tracking-tight flex items-center gap-1.5 truncate">
                FileSentinel
                <span className="text-[9px] font-semibold bg-emerald-50 text-emerald-700 px-1.5 py-0.5 rounded border border-emerald-200 uppercase">
                  User
                </span>
              </h2>
              <p className="text-xs text-slate-500 truncate">
                {user?.organizationName || 'Enterprise Desktop'}
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
                  id={`nav-user-${item.id}`}
                  onClick={() => {
                    setSelectedFileId(null);
                    setActiveTab(item.id);
                  }}
                  className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-medium transition-all cursor-pointer ${
                    isActive
                      ? 'bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100/80 border border-transparent'
                  }`}
                >
                  <span className={isActive ? 'text-emerald-600' : 'text-slate-400'}>{item.icon}</span>
                  {item.label}
                  {item.id === 'scan' && activeScan?.status === 'SCANNING' && (
                    <span className="ml-auto w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* User Account / Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50/60 text-xs">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="font-semibold text-slate-900 truncate">{user?.username || 'User'}</div>
              <div className="text-[10px] text-slate-500 font-mono">Standard Account</div>
            </div>
            <button
              onClick={() => logout()}
              title="Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-slate-200/60 transition-colors cursor-pointer"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Workspace */}
      <main className="flex-1 overflow-y-auto bg-slate-50">
        {selectedFileId ? (
          <FileDetailView
            fileId={selectedFileId}
            onBack={() => setSelectedFileId(null)}
          />
        ) : (
          <>
            {activeTab === 'home' && (
              <UserHomeView
                onStartScan={() => setActiveTab('scan')}
                onNavigateToCompliance={() => setActiveTab('compliance')}
                onNavigateToHistory={() => setActiveTab('history')}
                recentScanId={localRecentScanId}
              />
            )}

            {activeTab === 'scan' && (
              <UserScanView
                onScanComplete={handleScanComplete}
                activeScan={activeScan}
                setActiveScan={setActiveScan}
                isScanLocked={isScanLocked}
              />
            )}

            {activeTab === 'compliance' && (
              <UserAuditView recentScanId={localRecentScanId} />
            )}

            {activeTab === 'endpoint_compliance' && (
              <UserEndpointView />
            )}

            {activeTab === 'history' && (
              <UserHistoryView
                onNavigateToCompliance={(scanId) => {
                  if (scanId) setLocalRecentScanId(scanId);
                  setActiveTab('compliance');
                }}
              />
            )}

            {activeTab === 'reports' && (
              <UserReportsView />
            )}

            {activeTab === 'help' && (
              <UserHelpView />
            )}
          </>
        )}
      </main>
    </div>
  );
};

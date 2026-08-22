import React, { useState, useEffect, useRef } from 'react';
import {
  FolderSearch,
  FolderPlus,
  Play,
  Pause,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileText,
  AlertCircle,
  Clock,
  Info,
  Folder,
  UploadCloud,
  CheckCircle,
  Search,
  Zap
} from 'lucide-react';
import { ScanSession, FileItem } from '../../types';
import { api } from '../../services/api';

import { getFileOutcomeSummary, getFindingsSummary } from '../../services/canonicalSelectors';
import { Copy, Check } from 'lucide-react';

interface UserScanViewProps {
  onScanComplete: (scanId: string) => void;
  activeScan: ScanSession | null;
  setActiveScan: React.Dispatch<React.SetStateAction<ScanSession | null>>;
  isScanLocked?: boolean;
}

interface UploadedTarget {
  name: string;
  rootPath: string;
  fileCount: number;
  uploading: boolean;
  progress: number;
}

export const UserScanView: React.FC<UserScanViewProps> = ({
  onScanComplete,
  activeScan,
  setActiveScan,
  isScanLocked = false
}) => {
  const [selectedTarget, setSelectedTarget] = useState<UploadedTarget | null>(null);
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isPausing, setIsPausing] = useState<boolean>(false);
  const [isResuming, setIsResuming] = useState<boolean>(false);
  const [scanFiles, setScanFiles] = useState<FileItem[]>([]);
  const [fileSearch, setFileSearch] = useState<string>('');
  const [copiedPathId, setCopiedPathId] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const completionReportedRef = useRef<Set<string>>(new Set());

  // Polling for active scan progress and live file outcomes
  useEffect(() => {
    if (!activeScan) return;

    let progressTimer: any;
    let filesTimer: any;

    const fetchFiles = async (scanId: string) => {
      try {
        const files = await api.getScanFiles(scanId);
        setScanFiles(files || []);
      } catch (err) {
        console.warn('[UserScanView] Error fetching scan files:', err);
      }
    };

    fetchFiles(activeScan.scan_id);

    if (activeScan.status === 'SCANNING') {
      progressTimer = setInterval(async () => {
        try {
          const updated = await api.getScanProgress(activeScan.scan_id);
          if (updated) {
            setActiveScan(updated);
            if (updated.status === 'COMPLETED' || updated.status === 'FAILED') {
              clearInterval(progressTimer);
              clearInterval(filesTimer);
              fetchFiles(updated.scan_id);

              if (updated.status === 'COMPLETED' && !completionReportedRef.current.has(updated.scan_id)) {
                completionReportedRef.current.add(updated.scan_id);
                onScanComplete(updated.scan_id);
              }
            }
          }
        } catch (err) {
          console.error('[UserScanView] Error polling scan progress:', err);
        }
      }, 600);

      filesTimer = setInterval(() => {
        fetchFiles(activeScan.scan_id);
      }, 1200);
    }

    return () => {
      if (progressTimer) clearInterval(progressTimer);
      if (filesTimer) clearInterval(filesTimer);
    };
  }, [activeScan?.scan_id, activeScan?.status, onScanComplete, setActiveScan]);

  const handleFolderSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setErrorMessage(null);
    const fileList = Array.from(files) as File[];
    
    // Extract top-level directory name
    const firstFile = fileList[0];
    const firstPath = (firstFile as any).webkitRelativePath || firstFile.name;
    const folderName = firstPath.split('/')[0] || 'Uploaded Directory';

    setSelectedTarget({
      name: folderName,
      rootPath: '',
      fileCount: fileList.length,
      uploading: true,
      progress: 0
    });

    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }

    try {
      const uploadRes = await api.uploadDirectory(fileList, (pct) => {
        setSelectedTarget(prev => prev ? { ...prev, progress: pct } : null);
      });

      setSelectedTarget({
        name: uploadRes.folderName || folderName,
        rootPath: uploadRes.rootPath,
        fileCount: uploadRes.fileCount,
        uploading: false,
        progress: 100
      });
    } catch (err: any) {
      setSelectedTarget(null);
      setErrorMessage(err.message || 'Failed to upload selected folder files.');
    }
  };

  const handleStartScan = async () => {
    if (isScanLocked) {
      setErrorMessage('Scanning is locked due to clock synchronization drift.');
      return;
    }

    if (!selectedTarget || !selectedTarget.rootPath || selectedTarget.uploading) {
      setErrorMessage('Please select and upload a folder to scan.');
      return;
    }

    setErrorMessage(null);
    setIsStarting(true);

    try {
      const scanSession = await api.startScan([selectedTarget.rootPath]);
      if (scanSession && scanSession.scan_id) {
        setScanFiles([]);
        setActiveScan(scanSession);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to initialize scan session.');
    } finally {
      setIsStarting(false);
    }
  };

  const handlePauseScan = async () => {
    if (!activeScan) return;
    setIsPausing(true);
    try {
      const res = await api.pauseScan(activeScan.scan_id);
      if (res && res.scan) {
        setActiveScan(res.scan);
      } else {
        setActiveScan(prev => prev ? { ...prev, status: 'PAUSED' } : null);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to pause scan session.');
    } finally {
      setIsPausing(false);
    }
  };

  const handleResumeScan = async () => {
    if (!activeScan) return;
    setIsResuming(true);
    try {
      const res = await api.resumeScan(activeScan.scan_id);
      if (res && res.scan_id) {
        setActiveScan(res);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to resume scan session.');
    } finally {
      setIsResuming(false);
    }
  };

  const copyFilePath = (fileId: string, pathText: string) => {
    navigator.clipboard.writeText(pathText);
    setCopiedPathId(fileId);
    setTimeout(() => setCopiedPathId(null), 2000);
  };

  const isScanning = activeScan?.status === 'SCANNING';
  const isPaused = activeScan?.status === 'PAUSED';
  const isCompleted = activeScan?.status === 'COMPLETED';

  // Canonical Result Aggregation (Guarantees Total = Pass + Fail + Review)
  const fileSummary = getFileOutcomeSummary(activeScan, scanFiles);
  const totalFiles = activeScan?.total_files || fileSummary.total_discovered || (selectedTarget?.fileCount || 0);
  const processedFiles = activeScan?.processed_files || fileSummary.total_scanned;
  const progressPercent = totalFiles > 0 ? Math.min(100, Math.round((processedFiles / totalFiles) * 100)) : 0;

  const passedCount = fileSummary.passed;
  const failedCount = fileSummary.failed;
  const reviewCount = fileSummary.review;

  const filteredFiles = scanFiles.filter(f => {
    if (!fileSearch.trim()) return true;
    return f.filename.toLowerCase().includes(fileSearch.toLowerCase()) || f.path.toLowerCase().includes(fileSearch.toLowerCase());
  });

  return (
    <div className="max-w-5xl mx-auto px-6 py-8 space-y-8 animate-fade-in">
      {/* 1. Header */}
      <div className="border-b border-slate-200 pb-6">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight flex items-center gap-2.5">
          <span className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600">
            <FolderSearch className="w-5 h-5" />
          </span>
          Scan Files
        </h1>
        <p className="text-sm text-slate-500 mt-1">
          Select local directories or documents to evaluate DLP policies, compliance, and sensitive data leakage.
        </p>
      </div>

      {errorMessage && (
        <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl flex items-center gap-3 text-xs text-rose-800 shadow-2xs">
          <AlertCircle className="w-4 h-4 text-rose-600 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* 2. Active Scan Progress UI */}
      {(isScanning || isPaused || isCompleted) && (
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 sm:p-8 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className={`w-2.5 h-2.5 rounded-full ${
                  isScanning ? 'bg-emerald-500 animate-pulse' : isCompleted ? 'bg-emerald-600' : 'bg-amber-500'
                }`}></span>
                <h2 className="text-base font-bold text-slate-900">
                  {isScanning ? 'Scanning files...' : isCompleted ? 'Scan Completed Successfully' : 'Scan Paused'}
                </h2>
              </div>
              <p className="text-xs text-slate-500 mt-0.5 font-mono truncate max-w-md">
                Session: {activeScan?.scan_id}
              </p>
            </div>

            <div className="flex items-center gap-2">
              {isScanning && (
                <button
                  onClick={handlePauseScan}
                  disabled={isPausing}
                  className="px-3.5 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-lg border border-slate-200 flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Pause className="w-3.5 h-3.5" />
                  {isPausing ? 'Pausing...' : 'Pause Scan'}
                </button>
              )}

              {isPaused && (
                <button
                  onClick={handleResumeScan}
                  disabled={isResuming}
                  className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
                >
                  <Play className="w-3.5 h-3.5" />
                  {isResuming ? 'Resuming...' : 'Resume Scan'}
                </button>
              )}

              {isCompleted && (
                <button
                  onClick={() => onScanComplete(activeScan.scan_id)}
                  className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer shadow-xs"
                >
                  <CheckCircle className="w-3.5 h-3.5" />
                  View Audit Report
                </button>
              )}
            </div>
          </div>

          {/* Clean Light Progress Bar */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs font-medium text-slate-600">
              <span>{processedFiles} of {totalFiles} files inspected</span>
              <span className="font-bold text-emerald-700">{progressPercent}%</span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-3 overflow-hidden border border-slate-200/80">
              <div
                className="bg-emerald-600 h-full transition-all duration-300 rounded-full"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
          </div>

          {/* Live Canonical 3-Outcome File Metrics */}
          <div className="grid grid-cols-3 gap-4 pt-2">
            <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                Files Passed
              </div>
              <div className="text-2xl font-bold text-slate-900 font-mono">
                {passedCount}
              </div>
              <p className="text-[11px] text-slate-400">Clean — 0 violations</p>
            </div>

            <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-rose-700">
                <XCircle className="w-4 h-4 text-rose-600" />
                Files Failed
              </div>
              <div className="text-2xl font-bold text-rose-600 font-mono">
                {failedCount}
              </div>
              <p className="text-[11px] text-slate-400">Definitive violations</p>
            </div>

            <div className="bg-slate-50 border border-slate-200 p-4 rounded-xl space-y-1">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-700">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                Needs Review
              </div>
              <div className="text-2xl font-bold text-amber-600 font-mono">
                {reviewCount}
              </div>
              <p className="text-[11px] text-slate-400">Ambiguous detections</p>
            </div>
          </div>

          {/* Real Scanned Files Full Outcome Feed */}
          {scanFiles.length > 0 && (
            <div className="border border-slate-200 rounded-xl overflow-hidden mt-4">
              <div className="bg-slate-50 px-4 py-2.5 border-b border-slate-200 flex items-center justify-between">
                <span className="text-xs font-bold text-slate-700">
                  Scanned Files ({scanFiles.length})
                </span>
                <div className="relative w-48">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    placeholder="Filter file results..."
                    value={fileSearch}
                    onChange={(e) => setFileSearch(e.target.value)}
                    className="w-full bg-white border border-slate-200 rounded-lg pl-8 pr-2 py-1 text-[11px] text-slate-800 placeholder-slate-400 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              </div>

              <div className="max-h-72 overflow-y-auto divide-y divide-slate-100 bg-white">
                {filteredFiles.map((file) => {
                  const status = file.file_outcome || ((file.findings_count?.critical || 0) > 0 || (file.findings_count?.high || 0) > 0 ? 'FAIL' : (file.findings_count?.medium || 0) > 0 || (file.findings_count?.low || 0) > 0 ? 'REVIEW' : 'PASS');
                  const violatingRules = (file as any).violating_rules || [];
                  const reviewRules = (file as any).review_rules || [];
                  const allRules = violatingRules.length > 0 ? violatingRules : reviewRules.length > 0 ? reviewRules : file.findings?.map(f => f.rule_id).filter(Boolean) || [];
                  const ruleText = allRules.join(' · ');
                  const reasonText = file.outcome_reason || (status === 'PASS' ? 'Clean — No sensitive data detected' : file.findings?.map(f => f.title).join(', ') || 'Policy violation detected');
                  const confidence = (file as any).confidence || (status === 'FAIL' ? 'HIGH' : status === 'REVIEW' ? 'MEDIUM' : 'HIGH');

                  return (
                    <div key={file.file_id} className="p-4 space-y-2 hover:bg-slate-50 transition-colors">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0 flex-1">
                          <div className="font-bold text-sm text-slate-900 truncate font-mono">
                            {file.filename}
                          </div>
                          <div className="flex items-center gap-2 mt-0.5 group">
                            <span className="text-[11px] text-slate-400 font-mono truncate select-all">
                              {file.path}
                            </span>
                            <button
                              onClick={() => copyFilePath(file.file_id, file.path)}
                              title="Copy full file path"
                              className="text-slate-400 hover:text-slate-700 p-0.5 rounded cursor-pointer shrink-0"
                            >
                              {copiedPathId === file.file_id ? (
                                <Check className="w-3 h-3 text-emerald-600" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </div>

                        <span className={`px-2.5 py-1 rounded-md text-[11px] font-bold shrink-0 border uppercase tracking-wider ${
                          status === 'PASS'
                            ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                            : status === 'FAIL'
                            ? 'bg-rose-50 text-rose-700 border-rose-200'
                            : 'bg-amber-50 text-amber-700 border-amber-200'
                        }`}>
                          {status === 'PASS' ? '✓ PASSED' : status === 'FAIL' ? '✕ FAILED' : '? REVIEW'}
                        </span>
                      </div>

                      {/* Reason, Rules, and Confidence Details */}
                      <div className="text-xs text-slate-600 bg-slate-50/70 border border-slate-100 rounded-lg p-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="min-w-0">
                          <span className="font-medium text-slate-700">{reasonText}</span>
                          {ruleText && (
                            <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                              Rules: {ruleText}
                            </div>
                          )}
                        </div>
                        <div className="shrink-0 flex items-center gap-2 text-[10px] font-mono text-slate-400">
                          <span>Confidence: <strong className="text-slate-600">{confidence}</strong></span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* 3. Folder Selection Card */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6 sm:p-8 space-y-6">
        <div className="space-y-1 border-b border-slate-100 pb-4">
          <h2 className="text-base font-bold text-slate-900">
            Select Folder to Scan
          </h2>
          <p className="text-xs text-slate-500">
            Choose a directory on your computer. All files inside will be processed locally and tested against compliance rules.
          </p>
        </div>

        {/* Hidden Directory Input */}
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFolderSelect}
          // @ts-ignore
          webkitdirectory=""
          // @ts-ignore
          directory=""
          multiple
          className="hidden"
        />

        {/* Drag & Select Box */}
        <div
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-slate-200 hover:border-emerald-500/80 bg-slate-50/50 hover:bg-emerald-50/30 rounded-2xl p-8 flex flex-col items-center justify-center gap-3 cursor-pointer transition-all text-center group"
        >
          <div className="w-12 h-12 rounded-xl bg-emerald-50 border border-emerald-200 flex items-center justify-center text-emerald-600 group-hover:scale-105 transition-transform shadow-2xs">
            <FolderPlus className="w-6 h-6" />
          </div>
          <div>
            <span className="text-xs font-semibold text-slate-800 group-hover:text-emerald-700 block">
              {selectedTarget ? 'Change Folder Selection' : 'Click to Browse and Select a Folder'}
            </span>
            <span className="text-[11px] text-slate-400 mt-0.5 block">
              Supports documents (.xlsx, .docx, .pdf, .txt, .csv), scanned images, and code
            </span>
          </div>
        </div>

        {/* Selected Folder Details & Upload Progress */}
        {selectedTarget && (
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2.5 min-w-0">
              <Folder className="w-4 h-4 text-emerald-600 shrink-0" />
              <div className="truncate">
                <span className="font-semibold text-slate-900">{selectedTarget.name}</span>
                <span className="text-slate-500 ml-2 font-mono text-[11px]">
                  ({selectedTarget.fileCount.toLocaleString()} files queued)
                </span>
              </div>
            </div>

            {selectedTarget.uploading ? (
              <span className="px-2.5 py-1 bg-amber-50 text-amber-700 border border-amber-200 font-semibold rounded-lg text-[10px] uppercase shrink-0">
                Uploading {selectedTarget.progress}%
              </span>
            ) : (
              <span className="px-2.5 py-1 bg-emerald-50 text-emerald-700 border border-emerald-200 font-semibold rounded-lg text-[10px] uppercase shrink-0">
                Ready to Scan
              </span>
            )}
          </div>
        )}

        {/* Action Button */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <Info className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <span>Files are processed locally through the FileSentinel analyzer engine.</span>
          </div>

          <button
            id="btn-user-start-scan"
            onClick={handleStartScan}
            disabled={isStarting || isScanning || selectedTarget?.uploading}
            className="w-full sm:w-auto px-6 py-3 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 disabled:opacity-50 text-white text-xs font-semibold rounded-xl transition-all shadow-md shadow-emerald-600/10 flex items-center justify-center gap-2 cursor-pointer"
          >
            <Play className="w-4 h-4 fill-current" />
            {isStarting ? 'Starting Scan...' : isScanning ? 'Scan in Progress...' : 'START SCAN NOW'}
          </button>
        </div>
      </div>
    </div>
  );
};

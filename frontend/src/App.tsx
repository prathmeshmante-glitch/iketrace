import React, { useState, useEffect } from 'react';
import {
  CaptureAnalysisResult,
  PolicyDefinition,
  PolicyEvaluationReport,
  ScenarioDefinition,
  ScenarioResult,
  BaselineSnapshot,
  CryptoInventoryReport,
  AssessmentReport,
  AuditVerificationResult
} from './types';
import { api } from './services/api';
import { Navbar } from './components/Navbar';
import { Sidebar, TabKey } from './components/Sidebar';

import { OverviewPage } from './pages/OverviewPage';
import { CaptureUploadPage } from './pages/CaptureUploadPage';
import { SessionExplorerPage } from './pages/SessionExplorerPage';
import { PolicyEditorPage } from './pages/PolicyEditorPage';
import { FindingInspectorPage } from './pages/FindingInspectorPage';
import { ScenarioLabPage } from './pages/ScenarioLabPage';
import { DriftComparisonPage } from './pages/DriftComparisonPage';
import { TrafficPrivacyLabPage } from './pages/TrafficPrivacyLabPage';
import { CryptoInventoryPage } from './pages/CryptoInventoryPage';
import { EvidenceGraphPage } from './pages/EvidenceGraphPage';
import { ReportExportPage } from './pages/ReportExportPage';
import { SettingsPage } from './pages/SettingsPage';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [captures, setCaptures] = useState<CaptureAnalysisResult[]>([]);
  const [selectedCaptureId, setSelectedCaptureId] = useState<string | null>(null);
  const [policies, setPolicies] = useState<PolicyDefinition[]>([]);
  const [activePolicyId, setActivePolicyId] = useState<string>('POL-DEF-NIST-SP800-77');
  const [policyReport, setPolicyReport] = useState<PolicyEvaluationReport | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioDefinition[]>([]);
  const [scenarioResults, setScenarioResults] = useState<Record<string, ScenarioResult>>({});
  const [baselines, setBaselines] = useState<BaselineSnapshot[]>([]);
  const [cryptoInventory, setCryptoInventory] = useState<CryptoInventoryReport | null>(null);
  const [reports, setReports] = useState<AssessmentReport[]>([]);
  const [auditVerification, setAuditVerification] = useState<AuditVerificationResult | null>(null);
  const [latestAuditHash, setLatestAuditHash] = useState<string>('00000000');

  // Load initial environment data
  const loadInitialData = async () => {
    try {
      const caps = await api.listCaptures();
      setCaptures(caps);

      const pols = await api.listPolicies();
      setPolicies(pols);

      const scens = await api.listScenarios();
      setScenarios(scens);

      const bases = await api.listBaselines();
      setBaselines(bases);

      const reps = await api.listReports();
      setReports(reps);

      const auditRes = await api.verifyAuditChain();
      setAuditVerification(auditRes);

      const auditRecs = await api.getAuditRecords();
      if (auditRecs.length > 0) {
        setLatestAuditHash(auditRecs[auditRecs.length - 1].record_hash);
      }

      // Start with honest empty state (no auto-selected fixture)
      setSelectedCaptureId(null);
      setPolicyReport(null);
      setCryptoInventory(null);
    } catch (e) {
      console.error('Failed to load initial data from backend:', e);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  // When active capture changes
  const handleSelectCapture = async (id: string | null) => {
    if (!id) {
      setSelectedCaptureId(null);
      setPolicyReport(null);
      setCryptoInventory(null);
      return;
    }

    setSelectedCaptureId(id);
    // Reset state before loading to prevent cross-contamination
    setPolicyReport(null);
    setCryptoInventory(null);

    try {
      const [evalRep, inv, repList] = await Promise.all([
        api.evaluateAnalysisPolicy(id, activePolicyId),
        api.getAnalysisCryptoInventory(id),
        api.listAnalysisReports(id).catch(() => []),
      ]);
      setPolicyReport(evalRep);
      setCryptoInventory(inv);
      if (repList && repList.length > 0) {
        setReports((prev) => {
          const others = prev.filter((r) => r.target_id !== id);
          return [...repList, ...others];
        });
      }
    } catch (e) {
      console.error('Failed to load session analysis data:', e);
    }
  };

  // When policy is evaluated
  const handleEvaluatePolicy = async (policyId: string) => {
    setActivePolicyId(policyId);
    if (!selectedCaptureId) {
      throw new Error('No active packet capture selected. Please upload or select a capture session first.');
    }
    const rep = await api.evaluateAnalysisPolicy(selectedCaptureId, policyId);
    setPolicyReport(rep);
  };

  // When all scenarios are run
  const handleRunAllScenarios = async () => {
    try {
      const results = await api.runAllScenarios(activePolicyId);
      const resMap: Record<string, ScenarioResult> = {};
      results.forEach((r) => {
        resMap[r.scenario_id] = r;
      });
      setScenarioResults(resMap);
      setActiveTab('scenarios');
    } catch (e) {
      console.error(e);
    }
  };

  const currentCapture = captures.find((c) => c.capture_id === selectedCaptureId) || null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', backgroundColor: 'var(--bg-canvas)' }}>
      <Navbar
        captures={captures}
        selectedCaptureId={selectedCaptureId}
        onSelectCapture={handleSelectCapture}
        auditChainIntact={auditVerification?.chain_intact ?? true}
        latestAuditHash={latestAuditHash}
      />

      <div style={{ display: 'flex', flex: 1 }}>
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          badgeCounts={{
            findingsFailed: policyReport?.failed_count,
            sessionsCount: currentCapture?.session_count,
            scenariosCount: scenarios.length
          }}
        />

        <main style={{ flex: 1, padding: '2rem', maxWidth: '1440px', overflowX: 'hidden' }}>
          {activeTab === 'overview' && (
            <OverviewPage
              currentCapture={currentCapture}
              policyReport={policyReport}
              cryptoInventory={cryptoInventory}
              onNavigate={setActiveTab}
              onRunAllScenarios={handleRunAllScenarios}
            />
          )}

          {activeTab === 'upload' && (
            <CaptureUploadPage
              captures={captures}
              onCaptureUploaded={(newCap) => setCaptures((prev) => [newCap, ...prev])}
              onSelectCapture={handleSelectCapture}
              selectedCaptureId={selectedCaptureId}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'sessions' && (
            <SessionExplorerPage capture={currentCapture} />
          )}

          {activeTab === 'policy' && (
            <PolicyEditorPage
              policies={policies}
              activePolicyId={activePolicyId}
              onSelectPolicy={setActivePolicyId}
              onEvaluatePolicy={handleEvaluatePolicy}
              evaluationReport={policyReport}
              onNavigate={setActiveTab}
              selectedCaptureId={selectedCaptureId}
              selectedCaptureName={currentCapture?.filename}
            />
          )}

          {activeTab === 'findings' && (
            <FindingInspectorPage
              evaluationReport={policyReport}
              evidenceItems={currentCapture?.evidence_items || []}
            />
          )}

          {activeTab === 'scenarios' && (
            <ScenarioLabPage
              scenarios={scenarios}
              scenarioResults={scenarioResults}
              onScenarioResult={(res) => setScenarioResults((prev) => ({ ...prev, [res.scenario_id]: res }))}
              onAllScenarioResults={(results) => {
                const map: Record<string, ScenarioResult> = {};
                results.forEach((r) => { map[r.scenario_id] = r; });
                setScenarioResults(map);
              }}
            />
          )}

          {activeTab === 'drift' && (
            <DriftComparisonPage
              baselines={baselines}
              currentCapture={currentCapture}
              policyReport={policyReport}
              onBaselineCreated={(b) => setBaselines((prev) => [b, ...prev])}
            />
          )}

          {activeTab === 'privacy' && (
            <TrafficPrivacyLabPage currentCapture={currentCapture} />
          )}

          {activeTab === 'crypto' && (
            <CryptoInventoryPage inventory={cryptoInventory} />
          )}

          {activeTab === 'graph' && (
            <EvidenceGraphPage currentCapture={currentCapture} />
          )}

          {activeTab === 'reports' && (
            <ReportExportPage
              reports={reports}
              currentCapture={currentCapture}
              policies={policies}
              activePolicyId={activePolicyId}
              onReportGenerated={(rep) => setReports((prev) => [rep, ...prev])}
              onNavigate={setActiveTab}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsPage />
          )}
        </main>
      </div>
    </div>
  );
};

export default App;

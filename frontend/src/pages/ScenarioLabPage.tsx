import React, { useState } from 'react';
import { FlaskConical, Play, CheckCircle2, XCircle, Terminal, AlertTriangle, ArrowRight } from 'lucide-react';
import { ScenarioDefinition, ScenarioResult } from '../types';
import { api } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';

interface ScenarioLabPageProps {
  scenarios: ScenarioDefinition[];
  scenarioResults: Record<string, ScenarioResult>;
  onScenarioResult: (res: ScenarioResult) => void;
  onAllScenarioResults: (results: ScenarioResult[]) => void;
}

export const ScenarioLabPage: React.FC<ScenarioLabPageProps> = ({
  scenarios,
  scenarioResults,
  onScenarioResult,
  onAllScenarioResults,
}) => {
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [runningScenarioId, setRunningScenarioId] = useState<string | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string | null>(null);

  const handleRunSingle = async (id: string) => {
    setRunningScenarioId(id);
    try {
      const res = await api.runScenario(id);
      onScenarioResult(res);
      setSelectedScenarioId(id);
    } catch (e) {
      console.error(e);
    } finally {
      setRunningScenarioId(null);
    }
  };

  const handleRunAll = async () => {
    setIsRunningAll(true);
    try {
      const results = await api.runAllScenarios();
      onAllScenarioResults(results);
      if (results.length > 0) {
        setSelectedScenarioId(results[0].scenario_id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsRunningAll(false);
    }
  };

  const activeResult: ScenarioResult | undefined = selectedScenarioId
    ? scenarioResults[selectedScenarioId]
    : Object.values(scenarioResults)[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
            Security Scenario &amp; Regression Lab
          </h2>
          <p style={{ color: 'var(--text-muted)' }}>
            Reproducible defensive test harness using synthetic evidence. Validates secure baselines, prohibited suites, policy mismatches, and configuration corrections.
          </p>
        </div>

        <button
          onClick={handleRunAll}
          disabled={isRunningAll}
          className="btn-brutal btn-primary"
        >
          <Play size={16} fill="white" />
          <span>{isRunningAll ? 'Executing 8 Scenarios...' : 'Run All 8 Scenarios'}</span>
        </button>
      </div>

      {/* Synthetic Isolation Banner */}
      <div className="alert-brutal alert-info">
        <FlaskConical size={20} color="var(--accent-cobalt)" />
        <div>
          <div style={{ fontWeight: 700 }}>Isolated Laboratory Test Vectors</div>
          <div style={{ fontSize: '0.8rem' }}>
            All 8 scenario vectors are generated purely in memory for deterministic regression testing.
            Simulated findings are strictly labeled as synthetic and never presented as physical capture traffic.
          </div>
        </div>
      </div>

      {/* Scenarios Grid & Assertion Matrix Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: '1.5rem' }}>
        {/* Scenario Cards */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {scenarios.map((scen) => {
            const res = scenarioResults[scen.scenario_id];
            const isSelected = selectedScenarioId === scen.scenario_id;
            const isRunning = runningScenarioId === scen.scenario_id;

            return (
              <div
                key={scen.scenario_id}
                onClick={() => setSelectedScenarioId(scen.scenario_id)}
                style={{
                  border: isSelected ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                  backgroundColor: isSelected ? '#F4F7FF' : 'var(--bg-surface)',
                  boxShadow: isSelected ? 'var(--shadow-brutal)' : '2px 2px 0px var(--border-dark)',
                  padding: '1rem',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  transition: 'all 0.1s ease'
                }}
              >
                <div style={{ flex: 1, paddingRight: '1rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <span className="badge-brutal badge-na text-xs">{scen.category}</span>
                    <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                      {scen.scenario_id}
                    </span>
                  </div>
                  <h4 style={{ fontSize: '0.95rem', marginBottom: '0.25rem' }}>{scen.name}</h4>
                  <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.3' }}>
                    {scen.description}
                  </p>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem', flexShrink: 0 }}>
                  {res && (
                    <span className={`badge-brutal ${res.status === 'PASSED' ? 'badge-pass' : 'badge-fail'} text-xs`}>
                      {res.status === 'PASSED' ? <CheckCircle2 size={12} strokeWidth={3} /> : <XCircle size={12} strokeWidth={3} />}
                      <span>{res.status}</span>
                    </span>
                  )}
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRunSingle(scen.scenario_id);
                    }}
                    disabled={isRunning}
                    className="btn-brutal btn-neutral btn-sm"
                  >
                    {isRunning ? 'Running...' : 'Run Scenario'}
                  </button>
                </div>
              </div>
            );
          })}
        </div>

        {/* Selected Scenario Assertion Details */}
        <div className="card-brutal" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {activeResult ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
                <div>
                  <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    Execution Result • {activeResult.scenario_id}
                  </div>
                  <h3 style={{ fontSize: '1.1rem', marginTop: '0.25rem' }}>{activeResult.scenario_name}</h3>
                </div>
                <span className={`badge-brutal ${activeResult.status === 'PASSED' ? 'badge-pass' : 'badge-fail'}`}>
                  {activeResult.status}
                </span>
              </div>

              {/* Assertions Table */}
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                  Assertion Results ({activeResult.assertion_results.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {activeResult.assertion_results.map((ast) => (
                    <div
                      key={ast.assertion_id}
                      style={{
                        padding: '0.6rem 0.75rem',
                        border: '2px solid var(--border-dark)',
                        backgroundColor: ast.passed ? '#F4FEE4' : '#FFEBEA',
                        boxShadow: '2px 2px 0px var(--border-dark)'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.8rem' }}>
                          {ast.assertion_id}
                        </span>
                        <span className={`badge-brutal ${ast.passed ? 'badge-pass' : 'badge-fail'} text-xs`}>
                          {ast.passed ? 'PASSED' : 'FAILED'}
                        </span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{ast.details}</div>
                      <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                        Expected: <strong>{ast.expected}</strong> | Observed: <strong>{ast.observed}</strong>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Execution Audit Log */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                  <Terminal size={14} />
                  <span>Execution Audit Log</span>
                </div>
                <div style={{
                  padding: '0.75rem',
                  backgroundColor: '#1E1E1E',
                  color: '#A3E635',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.75rem',
                  lineHeight: '1.4',
                  maxHeight: '180px',
                  overflowY: 'auto',
                  border: '2px solid var(--border-dark)'
                }}>
                  {activeResult.execution_log.map((line, idx) => (
                    <div key={idx}>{line}</div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
              Click "Run All 8 Scenarios" or select a scenario card to run and view assertion results.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

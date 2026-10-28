import React from 'react';
import { CheckCircle2, XCircle, HelpCircle, MinusCircle, AlertTriangle } from 'lucide-react';
import { EvaluationOutcome, SeverityLevel } from '../types';

interface StatusBadgeProps {
  outcome?: EvaluationOutcome | string;
  severity?: SeverityLevel | string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ outcome, severity, size = 'md' }) => {
  if (outcome) {
    switch (outcome) {
      case 'PASS':
        return (
          <span className={`badge-brutal badge-pass ${size === 'sm' ? 'text-xs py-0.5' : ''}`} role="status" aria-label="Outcome: PASS">
            <CheckCircle2 size={size === 'sm' ? 12 : 14} strokeWidth={3} />
            <span>PASS</span>
          </span>
        );
      case 'FAIL':
        return (
          <span className={`badge-brutal badge-fail ${size === 'sm' ? 'text-xs py-0.5' : ''}`} role="status" aria-label="Outcome: FAIL">
            <XCircle size={size === 'sm' ? 12 : 14} strokeWidth={3} />
            <span>FAIL</span>
          </span>
        );
      case 'UNKNOWN':
        return (
          <span className={`badge-brutal badge-unknown ${size === 'sm' ? 'text-xs py-0.5' : ''}`} role="status" aria-label="Outcome: UNKNOWN">
            <HelpCircle size={size === 'sm' ? 12 : 14} strokeWidth={3} />
            <span>UNKNOWN</span>
          </span>
        );
      case 'NOT_APPLICABLE':
      case 'N/A':
        return (
          <span className={`badge-brutal badge-na ${size === 'sm' ? 'text-xs py-0.5' : ''}`} role="status" aria-label="Outcome: NOT APPLICABLE">
            <MinusCircle size={size === 'sm' ? 12 : 14} strokeWidth={2} />
            <span>N/A</span>
          </span>
        );
      default:
        return (
          <span className="badge-brutal badge-na">
            <span>{outcome}</span>
          </span>
        );
    }
  }

  if (severity) {
    switch (severity) {
      case 'CRITICAL':
        return (
          <span className="badge-brutal badge-fail">
            <AlertTriangle size={13} strokeWidth={3} />
            <span>CRITICAL</span>
          </span>
        );
      case 'HIGH':
        return (
          <span className="badge-brutal badge-orange">
            <span>HIGH</span>
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="badge-brutal badge-unknown">
            <span>MEDIUM</span>
          </span>
        );
      case 'LOW':
        return (
          <span className="badge-brutal badge-pass">
            <span>LOW</span>
          </span>
        );
      default:
        return (
          <span className="badge-brutal badge-na">
            <span>{severity}</span>
          </span>
        );
    }
  }

  return null;
};

import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, FlaskConical } from 'lucide-react';
import { useInvestigation } from '../hooks/useInvestigation.js';
import { readStashedMessage } from '../utils/session.js';
import ProgressStepper from '../components/report/ProgressStepper.jsx';
import ReportHeader, { exportReport } from '../components/report/ReportHeader.jsx';
import ExplanationPanel from '../components/report/ExplanationPanel.jsx';
import EvidenceSection from '../components/report/EvidenceSection.jsx';
import TlsSection from '../components/report/TlsSection.jsx';
import SecurityHeaders from '../components/report/SecurityHeaders.jsx';
import RedirectChain from '../components/report/RedirectChain.jsx';
import MessageAnalysis from '../components/report/MessageAnalysis.jsx';
import RegistryPanel from '../components/report/RegistryPanel.jsx';
import RiskScale from '../components/report/RiskScale.jsx';
import { CheckCoverage, Limitations, Recommendations } from '../components/report/SidePanels.jsx';
import { ErrorState, Skeleton } from '../components/ui/States.jsx';

function ReportSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-44 w-full rounded-xl" />
      <div className="grid gap-6 lg:grid-cols-3">
        <Skeleton className="h-80 rounded-xl lg:col-span-2" />
        <Skeleton className="h-80 rounded-xl" />
      </div>
    </div>
  );
}

export default function ReportPage() {
  const { id } = useParams();
  const { report, setReport, error, loading, reload } = useInvestigation(id);
  const messageText = useMemo(() => report?.message?.text || readStashedMessage(id), [report, id]);

  return (
    <div className="mx-auto max-w-7xl px-4 pb-24 pt-8 sm:px-6">
      {/* Back Link */}
      <Link
        to="/scanner"
        className="no-print mb-6 inline-flex items-center gap-1.5 font-mono text-xs text-white/50 hover:text-white transition-colors"
      >
        <ArrowLeft size={14} />
        <span>New scan</span>
      </Link>

      {loading && !report && <ReportSkeleton />}

      {error && !report && (
        <ErrorState
          title="Investigation Report Unavailable"
          message={error.message}
          action={
            <div className="flex gap-2">
              <button onClick={reload} className="btn-secondary px-3 py-1.5 text-xs">
                Retry Query
              </button>
              <Link to="/scanner" className="btn-ghost px-3 py-1.5 text-xs">
                Start New Investigation
              </Link>
            </div>
          }
        />
      )}

      {report?.status === 'processing' && (
        <div className="mx-auto max-w-2xl py-8">
          <ProgressStepper report={report} />
          {error && <p className="mt-4 text-center font-mono text-xs text-amber-300">{error.message}</p>}
        </div>
      )}

      {report?.status === 'failed' && (
        <div className="space-y-6">
          <ErrorState
            title="Investigation Pipeline Aborted"
            message={`${report.error?.message || 'The investigation could not be completed.'} This target has NOT been assessed and must not be treated as safe.`}
            action={<Link to="/scanner" className="btn-secondary px-3 py-1.5 text-xs">Initiate New Scan</Link>}
          />
          {report.steps && <ProgressStepper report={report} />}
        </div>
      )}

      {report?.status === 'completed' && (
        <div className="space-y-6">
          {report.demo && (
            <div className="flex items-start gap-2.5 rounded-lg border border-amber-400/25 bg-amber-400/[0.06] p-3 text-xs text-amber-200">
              <FlaskConical size={15} className="mt-0.5 shrink-0 text-amber-300" />
              <span>
                <strong className="font-semibold text-amber-300">Sample report.</strong> Demo data, not a live scan.
              </span>
            </div>
          )}

          {/* Report Header */}
          <ReportHeader report={report} onExport={() => exportReport(report)} />
          <RiskScale
            classification={report.classification}
            sections={[
              ['explanation-title', 'Summary'],
              ...(report.type === 'message' ? [['message-title', 'Message']] : []),
              ['evidence-title', 'Evidence'],
              ...(report.type === 'url'
                ? [
                    ['redirect-title', 'Redirects'],
                    ['tls-title', 'TLS'],
                    ['headers-title', 'Headers'],
                  ]
                : []),
              ['rec-title', 'Actions'],
              ['registry-title', 'On-chain'],
              ['lim-title', 'Limitations'],
            ]}
          />

          {/* Main 2-Column Findings Grid */}
          <div className="grid items-start gap-6 lg:grid-cols-3">
            {/* Left 2 Columns: Evidence, TLS, Headers, Message Forensics */}
            <div className="space-y-6 lg:col-span-2">
              <ExplanationPanel explanation={report.explanation} />
              {report.type === 'message' && <MessageAnalysis message={report.message} text={messageText} />}
              <EvidenceSection findings={report.findings} checks={report.checks} />
              {report.type === 'url' && (
                <>
                  <RedirectChain chain={report.redirectChain} />
                  <TlsSection tls={report.tls} />
                  <SecurityHeaders audit={report.securityHeaders} />
                </>
              )}
            </div>

            {/* Right Column: Recommendations, Coverage, Registry, Limitations */}
            <aside className="space-y-6">
              <Recommendations items={report.recommendations} />
              <CheckCoverage checks={report.checks} />
              <RegistryPanel report={report} onRegistered={(registry) => setReport((r) => ({ ...r, registry }))} />
              <Limitations items={report.limitations} />
            </aside>
          </div>
        </div>
      )}
    </div>
  );
}

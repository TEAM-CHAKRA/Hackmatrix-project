import { PageHeader } from '../components/ui/Glass.jsx';
import { useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldCheck, ShieldX, Loader2, Search, ExternalLink, HelpCircle, Info, Hash, CheckCircle2 } from 'lucide-react';
import { verifyReport } from '../services/api.js';
import { cx, formatDateTime } from '../utils/format.js';
import { ErrorState, Notice } from '../components/ui/States.jsx';

const HASH_RE = /^(0x)?[0-9a-f]{64}$/i;

const RESULT = {
  match: {
    label: 'Cryptographic Integrity Verified',
    desc: 'The recomputed SHA-256 hash matches the on-chain smart contract record bit-for-bit. The report has not been altered or tampered with since registration.',
    icon: ShieldCheck,
    badgeCls: 'border-signal/30 bg-signal/10 text-signal',
  },
  mismatch: {
    label: 'Cryptographic Integrity Mismatch',
    desc: 'The recomputed hash does not match the on-chain record. The stored report data has deviated from the canonical version anchored on the blockchain.',
    icon: ShieldX,
    badgeCls: 'border-red-400/40 bg-red-500/10 text-red-300',
  },
  not_registered: {
    label: 'No On-Chain Registration Found',
    desc: 'This report exists in local or database storage, but no transaction anchor has been submitted or confirmed on the target ledger.',
    icon: HelpCircle,
    badgeCls: 'border-white/20 bg-white/10 text-white/70',
  },
};

function HashRow({ label, value, highlight }) {
  return (
    <div className="kv-row">
      <dt className="kv-key text-xs text-white/50">{label}</dt>
      <dd className={cx('kv-val break-all font-mono text-xs', highlight || 'text-white/85')}>{value || '—'}</dd>
    </div>
  );
}

/** Static explainer: how the two hashes are produced and compared. No live data. */
function VerifyExplainer() {
  const Node = ({ k, title, text, accent }) => (
    <div className={cx('rounded-lg border glass-inset p-4', accent ? 'border-signal/35' : 'border-white/[0.08]')}>
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-white/40">{k}</div>
      <div className="mt-1 font-display text-[15px] font-semibold text-white">{title}</div>
      <p className="mt-1 text-[12.5px] leading-relaxed text-white/55">{text}</p>
    </div>
  );
  const Arrow = () => (
    <div className="flex items-center justify-center py-1 text-white/25 md:py-0" aria-hidden>
      <svg width="28" height="12" viewBox="0 0 28 12" className="rotate-90 md:rotate-0">
        <path d="M0 6h24M19 1l5 5-5 5" fill="none" stroke="currentColor" strokeWidth="1.5" />
      </svg>
    </div>
  );
  return (
    <section aria-labelledby="how-verify" className="rounded-xl border border-white/[0.08] glass-card p-6 ">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="how-verify" className="font-display text-base font-bold text-white">How verification works</h2>
        
      </div>
      <div className="mt-5 grid items-stretch gap-2 md:grid-cols-[1fr_auto_1fr_auto_1fr]">
        <div className="space-y-2">
          <Node k="Path A" title="Stored snapshot" text="Saved when the report was created." />
          <Node k="Path B" title="On-chain record" text="Written to the blockchain at registration." />
        </div>
        <Arrow />
        <div className="space-y-2">
          <Node k="A · recompute" title="SHA-256 now" text="Hashed again now." />
          <Node k="B · read" title="Registered hash" text="Read from the blockchain." />
        </div>
        <Arrow />
        <Node accent k="Result" title="Match or mismatch" text="Same hash = unchanged report." />
      </div>
    </section>
  );
}

export default function VerifyPage() {
  const [params] = useSearchParams();
  const [query, setQuery] = useState(params.get('id') || params.get('hash') || '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const autoRan = useRef(false);

  async function run(e) {
    e?.preventDefault();
    const q = query.trim();
    if (!q) {
      setError('Enter an Investigation ID (e.g. INV-...) or a 64-character SHA-256 hash.');
      return;
    }
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const body = HASH_RE.test(q) ? { reportHash: q.toLowerCase().replace(/^0x/, '') } : { investigationId: q };
      const res = await verifyReport(body);
      setResult(res.result);
    } catch (err) {
      setError(err.message || 'Verification execution failed.');
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!autoRan.current && query) {
      autoRan.current = true;
      run();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const r = result && (RESULT[result.integrity] || RESULT.not_registered);

  return (
    <div className="mx-auto max-w-4xl px-4 pb-24 pt-12 sm:px-6 sm:pt-16">
      <PageHeader align="center" eyebrow="Verify" title="Verify a" accent="report.">
        Check that a CYBERLENS report hasn't changed since it was registered on-chain.
      </PageHeader>

      {/* Verification Query Form */}
      <form onSubmit={run} className="mt-10 rounded-xl border border-white/[0.1] glass-card p-6 " noValidate>
        <label htmlFor="verify-q" className="eyebrow mb-2.5 block">
          Report ID or SHA-256 hash
        </label>
        <div className="flex flex-col gap-2.5 sm:flex-row">
          <div className="relative flex-1">
            <Hash size={15} className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-white/40" />
            <input
              id="verify-q"
              className="input pl-10 font-mono text-xs py-3 text-white"
              placeholder="e.g. INV-20261107-7F3A2C or 64-hex SHA-256 digest"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              autoComplete="off"
              spellCheck="false"
            />
          </div>
          <button className="btn-primary shrink-0 px-6 py-3 text-xs font-semibold" disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Search size={15} />}
            <span>{busy ? 'Verifying…' : 'Verify'}</span>
          </button>
        </div>

        {/* 4 Pipeline Steps */}
      </form>

      {/* Results and Comparison Details */}
      <div className="mt-6 space-y-6">
        {error && <ErrorState title="Verification Unsuccessful" message={error} />}

        {!result && !busy && <VerifyExplainer />}

        {result && r && (
          <div className="space-y-6">
            {/* Verdict Banner */}
            <div className={cx('flex items-start gap-4 rounded-xl border p-5 sm:p-6 backdrop-blur-md', r.badgeCls)}>
              <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-current bg-white/[0.04]">
                <r.icon size={22} />
              </span>
              <div>
                <div className="font-display text-lg font-bold text-white">{r.label}</div>
                <p className="mt-1 text-xs leading-relaxed text-white/70">{r.desc}</p>
              </div>
            </div>

            {/* Hash Comparison Table */}
            <section className="rounded-xl border border-white/[0.08] glass-card p-6 ">
              <h2 className="font-display text-base font-bold text-white border-b border-white/[0.06] pb-3">
                Cryptographic Fingerprint Audit
              </h2>
              <dl className="mt-2 divide-y divide-white/[0.04]">
                <HashRow
                  label="Computed Snapshot Hash"
                  value={result.computedHash}
                  highlight={result.integrity === 'match' ? 'text-signal font-medium' : undefined}
                />
                <HashRow
                  label="Registered On-Chain Hash"
                  value={result.onChainHash}
                  highlight={
                    result.integrity === 'mismatch'
                      ? 'text-red-300 font-medium'
                      : result.integrity === 'match'
                        ? 'text-signal font-medium'
                        : undefined
                  }
                />
                <HashRow label="Canonical Schema Version" value={result.canonicalVersion} />
              </dl>
            </section>

            {/* Transaction & Smart Contract Meta */}
            <section className="rounded-xl border border-white/[0.08] glass-card p-6 ">
              <h2 className="font-display text-base font-bold text-white border-b border-white/[0.06] pb-3">
                Ledger Transaction Records
              </h2>
              <dl className="mt-2 divide-y divide-white/[0.04]">
                <HashRow label="Report Identifier" value={result.investigationId} />
                <HashRow label="Blockchain Network" value={result.network} />
                <HashRow label="Contract Address" value={result.contractAddress} />
                <HashRow label="Transaction Hash" value={result.txHash} />
                <HashRow label="Block Number" value={result.blockNumber} />
                <HashRow label="Anchored Timestamp" value={result.timestamp && formatDateTime(result.timestamp)} />
              </dl>
              <div className="mt-5 flex flex-wrap gap-2 pt-2 border-t border-white/[0.06]">
                {result.explorerUrl && (
                  <a
                    href={result.explorerUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn-secondary px-3 py-1.5 text-xs font-mono"
                  >
                    <ExternalLink size={13} />
                    <span>View on Block Explorer</span>
                  </a>
                )}
                {result.investigationId && (
                  <Link
                    to={`/report/${encodeURIComponent(result.investigationId)}`}
                    className="btn-secondary px-3 py-1.5 text-xs font-mono"
                  >
                    <span>Inspect Full Report</span>
                  </Link>
                )}
              </div>
            </section>
          </div>
        )}

        <Notice icon={Info}>
          A match proves the report is unchanged. It does not prove the website is safe.
        </Notice>
      </div>
    </div>
  );
}

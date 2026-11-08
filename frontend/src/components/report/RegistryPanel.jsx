import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Blocks, Loader2, ExternalLink, AlertTriangle, ShieldCheck } from 'lucide-react';
import { registerReport } from '../../services/api.js';
import { formatDateTime, shortHash } from '../../utils/format.js';
import Tooltip from '../ui/Tooltip.jsx';

function Field({ label, value, mono = true, full }) {
  return (
    <div className="kv-row text-xs">
      <dt className="kv-key sm:w-28 text-white/50">{label}</dt>
      <dd className={mono ? 'kv-val font-mono text-[11px]' : 'text-xs text-white/85'} title={full || undefined}>
        {value ?? '—'}
      </dd>
    </div>
  );
}

export default function RegistryPanel({ report, onRegistered }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const reg = report.registry || { status: 'not_registered' };
  const canRegister = report.status === 'completed' && ['not_registered', 'failed'].includes(reg.status);

  async function register() {
    setBusy(true);
    setError('');
    try {
      const res = await registerReport(report.id);
      onRegistered?.(res.registry);
    } catch (err) {
      setError(err.message || 'Registration failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-5 " aria-labelledby="registry-title">
      <div className="border-b border-white/[0.06] pb-3">
        <h2 id="registry-title" className="font-display text-sm font-bold text-white flex items-center gap-2">
          <Blocks size={15} className="text-signal" />
          <Tooltip text="A SHA-256 fingerprint of the canonical snapshot is anchored on a blockchain (a local test chain or the Sepolia testnet), so anyone can later check that the findings were not altered.">
            <span>On-Chain Cryptographic Anchor</span>
          </Tooltip>
        </h2>
      </div>

      {reg.status === 'registered' ? (
        <>
          <div className="mt-3.5 inline-flex items-center gap-1.5 rounded-md border border-signal/30 bg-signal/10 px-2 py-1 text-xs text-signal font-mono font-medium">
            <ShieldCheck size={13} />
            <span>Anchored on {reg.network || 'blockchain'}</span>
          </div>

          <dl className="mt-3 divide-y divide-white/[0.04]">
            <Field label="Digest Hash" value={shortHash(reg.reportHash, 10, 8)} full={reg.reportHash} />
            <Field label="Transaction" value={shortHash(reg.txHash, 10, 8)} full={reg.txHash} />
            <Field label="Block" value={reg.blockNumber} />
            <Field label="Contract" value={shortHash(reg.contractAddress, 8, 6)} full={reg.contractAddress} />
            <Field label="Timestamp" value={formatDateTime(reg.timestamp)} mono={false} />
            {reg.revision != null && <Field label="Revision" value={reg.revision} />}
          </dl>

          <div className="mt-4 flex flex-wrap gap-2 border-t border-white/[0.06] pt-3">
            {reg.explorerUrl && (
              <a
                href={reg.explorerUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="btn-secondary px-3 py-1.5 text-xs font-mono"
              >
                <ExternalLink size={12} />
                <span>Block Explorer</span>
              </a>
            )}
            <Link to={`/verify?id=${encodeURIComponent(report.id)}`} className="btn-secondary px-3 py-1.5 text-xs font-mono">
              <ShieldCheck size={12} />
              <span>Verify Digest</span>
            </Link>
          </div>
        </>
      ) : reg.status === 'pending' ? (
        <div className="mt-4 flex items-center gap-2 text-xs text-white/70">
          <Loader2 size={14} className="animate-spin text-signal" />
          <span>Mined transaction pending confirmation...</span>
        </div>
      ) : (
        <>
          <p className="mt-3 text-xs leading-relaxed text-white/55">
            Store this report's SHA-256 fingerprint on-chain so anyone can verify it later.
          </p>
          {reg.status === 'failed' && (
            <p className="mt-2 text-xs text-red-300">Previous anchoring attempt failed{reg.error ? `: ${reg.error}` : '.'}</p>
          )}
          <button
            onClick={register}
            disabled={!canRegister || busy}
            className="btn-primary no-print mt-4 w-full py-2.5 text-xs font-semibold"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Blocks size={14} />}
            <span>{busy ? 'Registering…' : 'Register on-chain'}</span>
          </button>
          {report.status !== 'completed' && (
            <p className="mt-2 text-[10.5px] text-white/40">Only completed investigations can be anchored on-chain.</p>
          )}
          {error && (
            <p role="alert" className="mt-3 flex gap-1.5 rounded-lg border border-amber-400/30 bg-amber-400/10 p-2 text-xs text-amber-200">
              <AlertTriangle size={13} className="shrink-0 mt-0.5" />
              <span>{error}</span>
            </p>
          )}
        </>
      )}
    </section>
  );
}

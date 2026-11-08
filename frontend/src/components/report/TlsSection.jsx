import { Fragment } from 'react';
import { Lock, LockOpen, ArrowRight, ArrowDown, Info } from 'lucide-react';
import { TLS_NOTICE } from '../../utils/constants.js';
import { cx, formatDate } from '../../utils/format.js';
import { Chip } from '../ui/Badges.jsx';
import Tooltip from '../ui/Tooltip.jsx';

const TLS_STATUS = {
  valid: { label: 'Valid Certificate', tone: 'green' },
  expired: { label: 'Expired Certificate', tone: 'red' },
  hostname_mismatch: { label: 'Hostname Mismatch', tone: 'red' },
  untrusted_chain: { label: 'Untrusted Certificate Chain', tone: 'orange' },
  incomplete: { label: 'Incomplete TLS Metadata', tone: 'amber' },
  unavailable: { label: 'TLS Inspection Unavailable', tone: 'gray' },
  no_https: { label: 'HTTPS Protocol Not Available', tone: 'amber' },
};

const ROLE_LABEL = { leaf: 'Leaf Certificate', intermediate: 'Intermediate CA', root: 'Root CA' };

function Row({ k, tip, children }) {
  return (
    <div className="kv-row text-xs">
      <dt className="kv-key text-white/50">{tip ? <Tooltip text={tip}>{k}</Tooltip> : k}</dt>
      <dd className="kv-val font-mono">{children ?? <span className="text-white/40">Not available</span>}</dd>
    </div>
  );
}

function yesNo(v) {
  if (v === true) return <span className="text-signal font-semibold">Yes</span>;
  if (v === false) return <span className="text-red-300 font-semibold">No</span>;
  return null;
}

export default function TlsSection({ tls }) {
  if (!tls) return null;
  const st = TLS_STATUS[tls.status] || TLS_STATUS.incomplete;
  const unavailable = tls.status === 'unavailable';

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-6 " aria-labelledby="tls-title">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-3.5">
        <h2 id="tls-title" className="font-display text-base font-bold text-white flex items-center gap-2">
          {tls.httpsAvailable ? <Lock size={15} className="text-signal" /> : <LockOpen size={15} className="text-white/40" />}
          <span>TLS certificate</span>
        </h2>
        <Chip toneName={st.tone}>{st.label}</Chip>
      </div>

      <div className="mt-4 flex gap-2 rounded-lg border border-white/[0.06] glass-inset p-3 text-xs leading-relaxed text-white/70">
        <Info size={13} className="mt-0.5 shrink-0 text-signal" />
        <span>{TLS_NOTICE}</span>
      </div>

      {unavailable ? (
        <p className="mt-4 rounded-lg border border-dashed border-white/10 p-4 text-xs text-white/50">
          {tls.note || 'TLS certificate telemetry could not be resolved.'} No cryptographic conclusions were drawn.
        </p>
      ) : (
        <>
          {/* Certificate Hierarchy Chain */}
          {tls.chain?.length > 0 && (
            <div className="mt-5">
              <div className="eyebrow mb-2.5 flex items-center gap-2">
                <span>Certificate chain</span>
                {tls.chainTrusted === true && <span className="text-signal font-mono text-[10px]">• TRUSTED</span>}
                {tls.chainTrusted === false && <span className="text-orange-300 font-mono text-[10px]">• UNTRUSTED</span>}
              </div>
              <div className="flex flex-col gap-2 md:flex-row md:items-center">
                {tls.chain.map((c, i) => (
                  <Fragment key={i}>
                    <div className="min-w-0 flex-1 rounded-lg border border-white/[0.06] glass-inset p-3">
                      <div className="font-mono text-[10px] uppercase text-signal font-semibold">{ROLE_LABEL[c.role] || c.role}</div>
                      <div className="mt-1 break-words font-mono text-xs text-white/90">{c.subject}</div>
                      <div className="mt-1 text-[11px] text-white/45">
                        Issuer: <span className="text-white/60">{c.issuer}</span>
                      </div>
                      {c.validTo && <div className="mt-0.5 text-[10px] font-mono text-white/40">Expires {formatDate(c.validTo)}</div>}
                    </div>
                    {i < tls.chain.length - 1 && (
                      <div className="flex items-center justify-center text-white/30">
                        <ArrowRight size={14} className="hidden md:block" />
                        <ArrowDown size={14} className="md:hidden" />
                      </div>
                    )}
                  </Fragment>
                ))}
              </div>
            </div>
          )}

          {/* Key-Value Details */}
          <dl className="mt-5 divide-y divide-white/[0.04] border-t border-white/[0.06]">
            <Row k="HTTPS Protocol">{yesNo(tls.httpsAvailable)}</Row>
            <Row k="Certificate Validity Window">{yesNo(tls.valid)}</Row>
            <Row k="Valid From">{tls.validFrom && formatDate(tls.validFrom)}</Row>
            <Row k="Expires">
              {tls.validTo && (
                <>
                  <span>{formatDate(tls.validTo)}</span>
                  {typeof tls.daysRemaining === 'number' && (
                    <span className={cx('ml-2 text-[11px]', tls.daysRemaining < 0 ? 'text-red-300' : tls.daysRemaining < 15 ? 'text-amber-300' : 'text-white/40')}>
                      ({tls.daysRemaining < 0 ? `expired ${-tls.daysRemaining} days ago` : `${tls.daysRemaining} days remaining`})
                    </span>
                  )}
                </>
              )}
            </Row>
            <Row k="Issuer Entity">{tls.issuer}</Row>
            <Row k="Subject Common Name">{tls.subject}</Row>
            <Row k="Subject Alt. Names (SAN)" tip="Configured hostnames authorized under this certificate.">
              {tls.san?.length ? (
                <span className="flex flex-wrap gap-1">
                  {tls.san.map((s) => (
                    <span key={s} className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[11px]">{s}</span>
                  ))}
                </span>
              ) : null}
            </Row>
            <Row k="Target Hostname Match" tip="Whether visited hostname matches certificate SAN.">{yesNo(tls.hostnameMatch)}</Row>
            <Row k="Public Key Specification">{tls.publicKey && `${tls.publicKey.type} ${tls.publicKey.bits ? `${tls.publicKey.bits}-bit` : ''}`}</Row>
            <Row k="Signature Algorithm">{tls.signatureAlgorithm}</Row>
            <Row k="Certificate Transparency (CT)" tip="Public audit logs indexed via crt.sh.">
              {tls.ct && (tls.ct.status === 'completed' ? `${tls.ct.entries ?? '—'} public log entries recorded` : <span className="text-white/40">{tls.ct.note || 'Not checked'}</span>)}
            </Row>
            <Row k="Revocation Status">{tls.revocation && (tls.revocation.status === 'not_checked' ? <span className="text-white/40">Not checked</span> : tls.revocation.status)}</Row>
          </dl>
        </>
      )}
    </section>
  );
}

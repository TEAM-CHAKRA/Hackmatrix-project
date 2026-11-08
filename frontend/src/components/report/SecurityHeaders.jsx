import { CheckCircle2, XCircle } from 'lucide-react';
import Tooltip from '../ui/Tooltip.jsx';

const HEADER_TIPS = {
  'Strict-Transport-Security': 'HSTS mandates that compliant browsers communicate exclusively via HTTPS.',
  'Content-Security-Policy': 'Restricts unauthorized executable scripts and dynamic resources.',
  'X-Frame-Options': 'Protects against clickjacking attacks by blocking unauthorized framing.',
  'X-Content-Type-Options': 'Prevents browsers from MIME-sniffing away from declared content types.',
  'Referrer-Policy': 'Governs how much referral URI data is broadcast in outbound HTTP headers.',
};

export default function SecurityHeaders({ audit }) {
  if (!audit) return null;
  const unavailable = audit.status !== 'completed';

  return (
    <section className="rounded-xl border border-white/[0.08] glass-card p-6 " aria-labelledby="headers-title">
      <div className="border-b border-white/[0.06] pb-3">
        <h2 id="headers-title" className="font-display text-base font-bold text-white">
          Security headers
        </h2>
        <p className="mt-1 text-xs text-white/50">
          Missing headers are weaknesses, not proof of phishing.
        </p>
      </div>

      {unavailable ? (
        <p className="mt-4 rounded-lg border border-dashed border-white/10 p-4 text-xs text-white/50">
          {audit.note || 'HTTP security response headers could not be retrieved.'}
        </p>
      ) : (
        <>
          <div className="mt-4 overflow-hidden rounded-lg border border-white/[0.06] glass-inset">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-white/[0.06] glass-inset text-[11px] font-mono uppercase text-white/40">
                <tr>
                  <th className="py-2.5 px-3.5">Security Header</th>
                  <th className="py-2.5 px-3.5">Status</th>
                  <th className="py-2.5 px-3.5">Observed Directives</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04] font-mono">
                {audit.headers.map((h) => (
                  <tr key={h.name} className="hover:bg-white/[0.02]">
                    <td className="py-2.5 px-3.5 font-medium text-white/90">
                      <Tooltip text={HEADER_TIPS[h.name] || h.name}>
                        <span>{h.name}</span>
                      </Tooltip>
                    </td>
                    <td className="py-2.5 px-3.5">
                      {h.present ? (
                        <span className="inline-flex items-center gap-1 text-signal text-[11px] font-semibold">
                          <CheckCircle2 size={12} /> Present
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-amber-300 text-[11px]">
                          <XCircle size={12} /> Missing
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3.5 text-white/50 text-[11px] break-all">
                      {h.present ? h.value || 'Configured' : h.recommendation || 'Recommendation: Configure header'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {(audit.httpsRedirect !== undefined && audit.httpsRedirect !== null) && (
            <div className="mt-3.5 text-xs text-white/60 font-mono">
              Insecure HTTP to HTTPS Automatic Upgrade:{' '}
              <span className={audit.httpsRedirect ? 'text-signal font-semibold' : 'text-amber-300'}>
                {audit.httpsRedirect ? 'Enforced (Pass)' : 'Not Enforced (Weakness)'}
              </span>
            </div>
          )}

          {audit.cookies?.length > 0 && (
            <div className="mt-5 border-t border-white/[0.06] pt-3.5">
              <div className="eyebrow mb-2">Observed Session Cookies ({audit.cookies.length})</div>
              <div className="space-y-1 font-mono text-xs text-white/70">
                {audit.cookies.map((c) => (
                  <div key={c.name} className="flex flex-wrap items-center gap-2 rounded glass-inset p-2 border border-white/[0.04]">
                    <span className="font-semibold text-white/90">{c.name}</span>
                    <span className="text-white/20">|</span>
                    <span className={c.secure ? 'text-signal' : 'text-amber-300'}>Secure: {c.secure ? 'yes' : 'no'}</span>
                    <span className="text-white/20">|</span>
                    <span className={c.httpOnly ? 'text-signal' : 'text-amber-300'}>HttpOnly: {c.httpOnly ? 'yes' : 'no'}</span>
                    <span className="text-white/20">|</span>
                    <span className="text-white/50">SameSite: {c.sameSite || 'unset'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

import { PageHeader } from '../components/ui/Glass.jsx';
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import { Radio, RefreshCw, ExternalLink, ShieldCheck, Users, Filter, Database, AlertTriangle, Link2, Search } from 'lucide-react';
import { listCommunityReports, listRegistry } from '../services/api.js';
import { RiskBadge, Chip } from '../components/ui/Badges.jsx';
import { EmptyState, Skeleton } from '../components/ui/States.jsx';
import { CLASSIFICATIONS, CLASSIFICATION_ORDER, COMMUNITY_STATUS, THREAT_CATEGORIES, TX_STATUS } from '../utils/constants.js';
import { cx, formatDateTime, shortHash, titleCase } from '../utils/format.js';

function toFeed(registry, community) {
  const a = registry.map((r) => ({
    key: `inv-${r.investigationId}-${r.revision ?? 1}`,
    source: 'investigation',
    id: r.investigationId,
    classification: r.classification,
    category: r.category,
    timestamp: r.registeredAt,
    status: r.txStatus || 'unknown',
    intelMatches: r.intelMatches || [],
    providers: r.providers || [],
    txHash: r.txHash,
    explorerUrl: r.explorerUrl,
    network: r.network,
    revision: r.revision ?? 1,
  }));
  const b = community.map((c) => ({
    key: `com-${c.id}`,
    source: 'community',
    id: c.id,
    category: c.category,
    timestamp: c.submittedAt,
    status: c.status || 'pending_review',
    targetDisplay: c.targetDisplay,
    validation: c.validation,
    registry: c.registry,
    linkedInvestigationId: c.linkedInvestigationId,
  }));
  return [...a, ...b].sort((x, y) => new Date(y.timestamp || 0) - new Date(x.timestamp || 0));
}

function InvestigationItem({ item }) {
  const tx = TX_STATUS[item.status];
  return (
    <article className="rounded-xl border border-white/[0.08] glass-card p-5 shadow-sm transition-colors hover:border-white/20">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded bg-signal/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-signal border border-signal/20">
              <ShieldCheck size={12} /> VERIFIED INVESTIGATION
            </span>
            {item.category && (
              <span className="rounded bg-white/[0.06] px-2 py-0.5 font-mono text-[11px] text-white/70">
                {THREAT_CATEGORIES[item.category] || titleCase(item.category)}
              </span>
            )}
          </div>
          <Link
            to={`/report/${encodeURIComponent(item.id)}`}
            className="mt-2.5 inline-block font-mono text-sm font-semibold text-signal hover:underline"
          >
            {item.id}
          </Link>
        </div>
        <RiskBadge classification={item.classification} />
      </div>

      {/* External TI match details */}
      <div className="my-3.5 rounded-lg border border-white/[0.05] glass-inset p-3 text-xs">
        <div className="font-mono text-[10.5px] uppercase text-white/40 mb-1.5">Intelligence Attribution</div>
        {item.intelMatches.length ? (
          <ul className="flex flex-wrap gap-1.5">
            {item.intelMatches.map((m, i) => (
              <li key={i} className="rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 font-mono text-[11px] text-red-200">
                <span>{m.provider}</span>
                {m.threatType && <span className="text-red-300 font-semibold"> · {m.threatType}</span>}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-white/45 text-[11.5px]">
            No positive malicious match recorded{item.providers.length ? ` (Audited: ${item.providers.join(', ')})` : ''}.
          </p>
        )}
      </div>

      {/* Footer Meta */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-white/[0.06] pt-3 text-xs text-white/50">
        <span className="font-mono text-[11px]">{formatDateTime(item.timestamp)}</span>
        <Chip toneName={tx?.tone || 'gray'}>{tx?.label || titleCase(item.status)}</Chip>
        <span className="font-mono text-[11px]">Rev. {item.revision}</span>
        {item.txHash && (
          item.explorerUrl ? (
            <a
              href={item.explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-mono text-[11px] text-white/60 hover:text-white"
            >
              Tx: {shortHash(item.txHash, 6, 4)} <ExternalLink size={10} />
            </a>
          ) : (
            <span className="font-mono text-[11px]">Tx: {shortHash(item.txHash, 6, 4)}</span>
          )
        )}
      </div>
    </article>
  );
}

function CommunityItem({ item }) {
  const st = COMMUNITY_STATUS[item.status] || { label: titleCase(item.status), tone: 'gray' };
  return (
    <article className="rounded-xl border border-dashed border-amber-400/25 glass-card p-5 shadow-sm transition-colors hover:border-amber-400/40">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded bg-amber-400/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-amber-300 border border-amber-400/20">
              <Users size={12} /> COMMUNITY REPORT · UNVERIFIED
            </span>
            {item.category && (
              <span className="rounded bg-white/[0.06] px-2 py-0.5 font-mono text-[11px] text-white/70">
                {THREAT_CATEGORIES[item.category] || titleCase(item.category)}
              </span>
            )}
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-white/90">{item.id}</div>
          {item.targetDisplay && (
            <div className="mt-1 break-all font-mono text-xs text-white/50">{item.targetDisplay}</div>
          )}
        </div>
        <Chip toneName={st.tone}>{st.label}</Chip>
      </div>
      <div className="mb-3" />

      {/* Footer Meta */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-white/[0.06] pt-3 text-xs text-white/50">
        <span className="font-mono text-[11px]">{formatDateTime(item.timestamp)}</span>
        {item.validation && (
          <span className="font-mono text-[11px]">
            <span className="text-signal">{item.validation.confirms ?? 0} confirms</span> ·{' '}
            <span className="text-orange-300">{item.validation.disputes ?? 0} disputes</span>
          </span>
        )}
        {item.registry?.status === 'registered' && <Chip toneName="cyan">On-chain</Chip>}
        {item.linkedInvestigationId && (
          <Link
            to={`/report/${encodeURIComponent(item.linkedInvestigationId)}`}
            className="inline-flex items-center gap-1 text-signal hover:underline text-xs"
          >
            <Link2 size={11} /> Linked Investigation
          </Link>
        )}
      </div>
    </article>
  );
}

export default function ThreatFeedPage() {
  const [state, setState] = useState({ loading: true, registry: [], community: [], errors: {}, demo: false });
  const [source, setSource] = useState('all');
  const [classification, setClassification] = useState('all');
  const [status, setStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');

  async function load() {
    setState((s) => ({ ...s, loading: true }));
    const [reg, com] = await Promise.allSettled([listRegistry(), listCommunityReports()]);
    setState({
      loading: false,
      registry: reg.status === 'fulfilled' ? reg.value.items || [] : [],
      community: com.status === 'fulfilled' ? com.value.items || [] : [],
      errors: {
        registry: reg.status === 'rejected' ? reg.reason?.message : null,
        community: com.status === 'rejected' ? com.reason?.message : null,
      },
      demo: (reg.status === 'fulfilled' && reg.value.demo) || (com.status === 'fulfilled' && com.value.demo),
    });
  }

  useEffect(() => {
    load();
  }, []);

  const feed = useMemo(() => toFeed(state.registry, state.community), [state.registry, state.community]);

  const statusOptions = useMemo(() => {
    const seen = [...new Set(feed.filter((f) => source === 'all' || f.source === source).map((f) => f.status))];
    return [['all', 'All Statuses'], ...seen.map((s) => [s, TX_STATUS[s]?.label || COMMUNITY_STATUS[s]?.label || titleCase(s)])];
  }, [feed, source]);

  const filtered = feed.filter((f) => {
    if (source !== 'all' && f.source !== source) return false;
    if (classification !== 'all' && (f.source !== 'investigation' || f.classification !== classification)) return false;
    if (status !== 'all' && f.status !== status) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchId = f.id?.toLowerCase().includes(q);
      const matchTarget = f.targetDisplay?.toLowerCase().includes(q);
      const matchCat = f.category?.toLowerCase().includes(q);
      const matchProv = f.providers?.some((p) => p.toLowerCase().includes(q));
      if (!matchId && !matchTarget && !matchCat && !matchProv) return false;
    }
    return true;
  });

  const stats = [
    { label: 'Verified Investigations', count: state.registry.length, icon: ShieldCheck, color: 'text-signal' },
    { label: 'Community Threat Submissions', count: state.community.length, icon: Users, color: 'text-amber-300' },
    { label: 'Confirmed Malicious Entities', count: state.registry.filter((r) => r.classification === 'confirmed_malicious').length, icon: AlertTriangle, color: 'text-red-400' },
  ];

  const bothFailed = state.errors.registry && state.errors.community;

  return (
    <div className="mx-auto max-w-7xl px-4 pb-24 pt-12 sm:px-6 sm:pt-16">
      <PageHeader
        eyebrow="Threat feed"
        title="Threat"
        accent="feed."
        action={
          <button
          onClick={load}
          className="btn-secondary self-start px-4 py-2.5 text-xs font-semibold lg:self-auto"
          disabled={state.loading}
        >
          <RefreshCw size={13} className={state.loading ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
        }
      >
        Registered investigations and community reports, in one place.
      </PageHeader>

      {/* Top Stat Metrics */}
      <div className="mt-8 grid gap-4 sm:grid-cols-3">
        {stats.map(({ label, count, icon: Icon, color }) => (
          <div key={label} className="rounded-xl border border-white/[0.08] glass-card p-5 flex items-center gap-4">
            <span className={`flex h-11 w-11 items-center justify-center rounded-lg border border-white/10 glass-inset ${color}`}>
              <Icon size={20} />
            </span>
            <div>
              <div className="font-mono text-2xl font-bold text-white">{state.loading ? '—' : count}</div>
              <div className="text-xs text-white/50">{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Search & Filter Toolbar */}
      <div className="mt-8 rounded-xl border border-white/[0.08] glass-card p-4 ">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {/* Search Input */}
          <div className="relative">
            <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-white/40" />
            <input
              type="text"
              placeholder="Search by ID, domain, provider..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="input pl-9 py-2 text-xs font-mono"
            />
          </div>

          {/* Source Select */}
          <div className="relative">
            <Database size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-white/40" />
            <select
              value={source}
              onChange={(e) => {
                setSource(e.target.value);
                setStatus('all');
                if (e.target.value === 'community') setClassification('all');
              }}
              className="input pl-9 py-2 text-xs appearance-none [&>option]:glass-card"
            >
              <option value="all">All Sources</option>
              <option value="investigation">Verified Investigations</option>
              <option value="community">Community Submissions</option>
            </select>
          </div>

          {/* Classification Select */}
          <div className="relative">
            <Radio size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-white/40" />
            <select
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
              disabled={source === 'community'}
              className="input pl-9 py-2 text-xs appearance-none disabled:opacity-40 [&>option]:glass-card"
            >
              <option value="all">All Classifications</option>
              {CLASSIFICATION_ORDER.map((k) => (
                <option key={k} value={k}>
                  {CLASSIFICATIONS[k].label}
                </option>
              ))}
            </select>
          </div>

          {/* Status Select */}
          <div className="relative">
            <Filter size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-white/40" />
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="input pl-9 py-2 text-xs appearance-none [&>option]:glass-card"
            >
              {statusOptions.map(([val, lbl]) => (
                <option key={val} value={val}>
                  {lbl}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Partial Errors Notice */}
      {!state.loading && !bothFailed && (state.errors.registry || state.errors.community) && (
        <div className="mt-4 flex items-start gap-2 rounded-lg border border-amber-400/30 bg-amber-400/10 p-3 text-xs text-amber-200">
          <AlertTriangle size={14} className="mt-0.5 shrink-0 text-amber-400" />
          <span>{state.errors.registry ? `Registry adapter unavailable: ${state.errors.registry}` : `Community feed offline: ${state.errors.community}`}</span>
        </div>
      )}

      {/* Feed List */}
      <div className="mt-6">
        {state.loading && (
          <div className="grid gap-4 md:grid-cols-2">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-44 w-full rounded-xl" />
            ))}
          </div>
        )}

        {!state.loading && bothFailed && (
          <EmptyState
            icon={AlertTriangle}
            title="Threat feed feeds unreachable"
            message={state.errors.registry}
            action={
              <button onClick={load} className="btn-secondary mt-2 text-xs">
                Retry Connection
              </button>
            }
          />
        )}

        {!state.loading && !bothFailed && filtered.length === 0 && (
          <EmptyState
            icon={Radio}
            title={feed.length ? 'No intelligence reports match filters' : 'No threat telemetry on record'}
            message={
              feed.length
                ? 'Try adjusting search terms, classification filters, or source selections.'
                : state.demo
                  ? 'Demo mode initializes with empty dynamic feed tables. Complete an investigation to generate an entry.'
                  : 'Start a new investigation or report a community threat to populate this ledger.'
            }
            action={
              !feed.length && (
                <div className="mt-3 flex gap-2">
                  <Link to="/scanner" className="btn-primary text-xs">
                    Start a Scan
                  </Link>
                  <Link to="/community" className="btn-secondary text-xs">
                    Report a Threat
                  </Link>
                </div>
              )
            }
          />
        )}

        {!state.loading && filtered.length > 0 && (
          <div className="grid gap-4 md:grid-cols-2">
            {filtered.map((item) => (
              <div key={item.key}>
                {item.source === 'investigation' ? (
                  <InvestigationItem item={item} />
                ) : (
                  <CommunityItem item={item} />
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

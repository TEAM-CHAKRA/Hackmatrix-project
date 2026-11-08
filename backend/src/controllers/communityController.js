import crypto from 'node:crypto';
import { z } from 'zod';
import { generateCommunityId } from '../utils/idGenerator.js';
import { repository } from '../store/repository.js';
import { sendSuccess, AppError } from '../utils/response.js';
import { ERROR_CODES, THREAT_CATEGORIES, COMMUNITY_REPORT_STATUSES } from '../config/constants.js';
import { env } from '../config/env.js';

/**
 * Phase 7 — Community threat reports.
 *
 * - Anonymous submissions allowed (rate-limited); signed-in users are recorded
 *   privately as the submitter. Targets are STORED, never fetched (no SSRF).
 * - Community reports are always unverified and never get a risk
 *   classification of their own.
 * - Public listings show a redacted `targetDisplay` (URL without query or
 *   credentials, masked emails and phone numbers) and hide rejected reports.
 * - One vote per voter (signed-in user, or a salted hash of the IP); a voter
 *   may switch their vote. Three or more votes move a report to under_review.
 * - Only admins set validated / disputed / rejected. Only validated reports can
 *   be anchored on-chain (POST /api/registry/register { communityReportId }).
 */

const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})$/i;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@.]+(\.[^\s@.]+)*\.[^\s@.]{2,}$/;
const PHONE_RE = /^\+?[\d\s().-]{7,20}$/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g;

const VOTES_FOR_REVIEW = 3;

function targetProblem(type, raw) {
  const t = raw.trim();
  if (type === 'url') {
    try {
      const u = new URL(t);
      if (!['http:', 'https:'].includes(u.protocol)) return 'Only http:// or https:// links can be reported.';
      if (!u.hostname.includes('.')) return 'Enter a full link, e.g. https://suspicious.example/login';
      return null;
    } catch {
      return 'Enter a valid link, e.g. https://suspicious.example/login';
    }
  }
  if (type === 'domain') return DOMAIN_RE.test(t) ? null : 'Enter a valid domain, e.g. suspicious.example';
  if (type === 'email') return EMAIL_RE.test(t) ? null : 'Enter a valid email address.';
  if (type === 'phone') {
    const digits = t.replace(/\D/g, '');
    return PHONE_RE.test(t) && digits.length >= 7 && digits.length <= 15 ? null : 'Enter a valid phone number.';
  }
  return 'Unknown target type.';
}

export const submitCommunityReportSchema = z
  .object({
    targetType: z.enum(['url', 'domain', 'phone', 'email']),
    target: z.string().trim().min(1, 'Target is required').max(2048),
    category: z.enum(THREAT_CATEGORIES),
    description: z
      .string()
      .transform((d) => d.replace(CONTROL_RE, '').trim())
      .pipe(z.string().min(20, 'Description must be at least 20 characters.').max(1000, 'Description must not exceed 1000 characters.')),
  })
  .strict()
  .superRefine((d, ctx) => {
    const problem = targetProblem(d.targetType, d.target);
    if (problem) ctx.addIssue({ code: 'custom', path: ['target'], message: problem });
  });

export const voteCommunityReportSchema = z.object({ voteType: z.enum(['confirm', 'dispute']) }).strict();

export const updateStatusSchema = z
  .object({
    status: z.enum(COMMUNITY_REPORT_STATUSES),
    linkedInvestigationId: z.string().regex(/^INV-\d{8}-[0-9A-F]{16}$/i).optional(),
  })
  .strict();

/** Safe-to-display form of a reported target. */
export function displayTarget(type, raw) {
  const t = raw.trim();
  if (type === 'url') {
    try {
      const u = new URL(t);
      return `${u.hostname}${u.pathname === '/' ? '' : u.pathname}`.slice(0, 200);
    } catch {
      return t.replace(/^https?:\/\//i, '').split(/[?#]/)[0].slice(0, 200);
    }
  }
  if (type === 'domain') return t.toLowerCase();
  if (type === 'email') {
    const [local, domain] = t.toLowerCase().split('@');
    return `${local.slice(0, 1)}${'•'.repeat(Math.max(2, Math.min(6, local.length - 1)))}@${domain}`;
  }
  // phone: keep country code / first digits and the last 3
  const digits = t.replace(/\D/g, '');
  const plus = t.trim().startsWith('+') ? '+' : '';
  return `${plus}${digits.slice(0, 3)}${'•'.repeat(Math.max(3, digits.length - 6))}${digits.slice(-3)}`;
}

function publicView(r) {
  return {
    id: r.id,
    targetType: r.targetType,
    category: r.category,
    targetDisplay: r.targetDisplay,
    description: r.description,
    submittedAt: r.submittedAt,
    status: r.status,
    validation: r.validation || { confirms: 0, disputes: 0 },
    registry: r.registry || undefined,
    linkedInvestigationId: r.linkedInvestigationId || undefined,
  };
}

function voterKey(req) {
  if (req.auth?.userId) return `u:${req.auth.userId}`;
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  return `ip:${crypto.createHmac('sha256', env.SESSION_SECRET).update(ip).digest('hex').slice(0, 32)}`;
}

const notFound = (id) => new AppError(`Community report '${id}' was not found.`, { code: ERROR_CODES.NOT_FOUND, status: 404 });

/** POST /api/community/reports */
export async function submitCommunityReport(req, res, next) {
  try {
    const { targetType, target, category, description } = req.body;
    const report = {
      id: generateCommunityId(),
      targetType,
      target: target.trim(), // stored, never fetched; never returned publicly
      targetDisplay: displayTarget(targetType, target),
      category,
      description,
      status: 'pending_review',
      validation: { confirms: 0, disputes: 0 },
      voters: {},
      submittedBy: req.auth?.userId || null,
      submittedAt: new Date().toISOString(),
    };
    await repository.createCommunityReport(report);
    return res.status(201).json({ success: true, report: { id: report.id, status: report.status } });
  } catch (err) {
    next(err);
  }
}

/** GET /api/community/reports — rejected reports are hidden (admins see all). */
export async function listCommunityReports(req, res, next) {
  try {
    const isAdmin = req.auth?.role === 'admin';
    const reports = await repository.listCommunityReports();
    const items = reports.filter((r) => isAdmin || r.status !== 'rejected').map(publicView);
    return sendSuccess(res, { items });
  } catch (err) {
    next(err);
  }
}

/** GET /api/community/reports/:id */
export async function getCommunityReport(req, res, next) {
  try {
    const r = await repository.getCommunityReport(req.params.id);
    if (!r || (r.status === 'rejected' && req.auth?.role !== 'admin')) throw notFound(req.params.id);
    return sendSuccess(res, { report: publicView(r) });
  } catch (err) {
    next(err);
  }
}

/** POST /api/community/reports/:id/vote  { voteType: confirm | dispute } — one vote per voter. */
export async function voteCommunityReport(req, res, next) {
  try {
    const { id } = req.params;
    const { voteType } = req.body;
    const report = await repository.getCommunityReport(id);
    if (!report || report.status === 'rejected') throw notFound(id);

    const key = voterKey(req);
    const voters = { ...(report.voters || {}) };
    const validation = { confirms: 0, disputes: 0, ...(report.validation || {}) };
    const previous = voters[key];

    if (previous !== voteType) {
      if (previous === 'confirm') validation.confirms = Math.max(0, validation.confirms - 1);
      if (previous === 'dispute') validation.disputes = Math.max(0, validation.disputes - 1);
      if (voteType === 'confirm') validation.confirms += 1;
      else validation.disputes += 1;
      voters[key] = voteType;
    }

    const updates = { voters, validation };
    if (report.status === 'pending_review' && validation.confirms + validation.disputes >= VOTES_FOR_REVIEW) {
      updates.status = 'under_review';
    }
    const updated = await repository.updateCommunityReport(id, updates);
    return sendSuccess(res, {
      report: { id: updated.id, status: updated.status, validation: updated.validation, yourVote: voteType, changed: previous !== voteType },
    });
  } catch (err) {
    next(err);
  }
}

/** PATCH /api/community/reports/:id/status — admin only. */
export async function updateCommunityReportStatus(req, res, next) {
  try {
    const { id } = req.params;
    const report = await repository.getCommunityReport(id);
    if (!report) throw notFound(id);
    const updates = { status: req.body.status, reviewedBy: req.auth.userId, reviewedAt: new Date().toISOString() };
    if (req.body.status === 'validated') updates.validatedAt = updates.reviewedAt;
    if (req.body.linkedInvestigationId) {
      const inv = await repository.getInvestigation(req.body.linkedInvestigationId);
      if (!inv) throw new AppError('The linked investigation was not found.', { code: ERROR_CODES.VALIDATION_ERROR, status: 400 });
      updates.linkedInvestigationId = inv.id;
    }
    if (report.registry?.status === 'registered' && req.body.status !== 'validated') {
      throw new AppError('This report is anchored on-chain as validated; its status can no longer be changed here.', { code: ERROR_CODES.CONFLICT, status: 409 });
    }
    const updated = await repository.updateCommunityReport(id, updates);
    return sendSuccess(res, { report: publicView(updated) });
  } catch (err) {
    next(err);
  }
}

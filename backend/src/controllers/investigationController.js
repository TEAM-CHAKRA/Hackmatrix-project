import { z } from 'zod';
import { generateInvestigationId } from '../utils/idGenerator.js';
import { repository } from '../store/repository.js';
import { sendSuccess, sendError, AppError } from '../utils/response.js';
import { ERROR_CODES, DEFAULT_STEPS } from '../config/constants.js';
import { validateTargetUrl, resolveAndValidate } from '../services/ssrfValidator.js';
import { investigationQueue } from '../jobs/investigationQueue.js';

export const createInvestigationSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('url'),
    target: z.string().url('Target must be a valid URL.').max(2048, 'URL must not exceed 2048 characters.'),
  }),
  z.object({
    type: z.literal('message'),
    content: z.string().min(10, 'Message must be at least 10 characters.').max(5000, 'Message must not exceed 5000 characters.'),
  }),
]);

/**
 * POST /api/investigations
 * Initiates an investigation, enqueues background worker, and immediately returns 202 Accepted
 */
export async function createInvestigation(req, res, next) {
  try {
    const { type } = req.body;
    const id = generateInvestigationId();
    const steps = (DEFAULT_STEPS[type] || DEFAULT_STEPS.url).map((s) => ({ ...s }));

    let targetDisplay = '';
    let targetHost = '';
    let validatedIp = null;
    let family = null;
    let addresses = null;

    if (type === 'url') {
      // Phase 2 SSRF Validation: run validateTargetUrl and resolveAndValidate before creating record
      const { parsed } = validateTargetUrl(req.body.target);
      const resolver = req.app?.locals?.resolver;
      const resolved = await resolveAndValidate(parsed.hostname, {
        resolver,
        _dangerouslyAllowLocalhostForTesting: req.app?.locals?._dangerouslyAllowLocalhostForTesting,
      });

      validatedIp = resolved.ip;
      family = resolved.family;
      addresses = resolved.addresses;

      targetHost = parsed.hostname;
      // Strip query parameters for safe initial display
      targetDisplay = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
    } else {
      targetDisplay = 'Submitted message';
    }

    const initialRecord = {
      id,
      type,
      status: 'processing',
      targetRaw: type === 'url' ? req.body.target : req.body.content,
      target: {
        display: targetDisplay,
        host: targetHost || undefined,
      },
      steps,
      checks: [],
      createdAt: new Date().toISOString(),
    };

    await repository.createInvestigation(initialRecord);

    // Enqueue background processing job without awaiting execution
    investigationQueue.enqueue({
      investigationId: id,
      type,
      target: req.body.target,
      content: req.body.content,
      validatedIp,
      family,
      addresses,
      resolver: req.app?.locals?.resolver,
      fetchFn: req.app?.locals?.fetchFn,
      requestFn: req.app?.locals?.requestFn,
      tlsConnectFn: req.app?.locals?.tlsConnectFn,
      _dangerouslyAllowLocalhostForTesting: req.app?.locals?._dangerouslyAllowLocalhostForTesting,
      _portOverrideForTesting: req.app?.locals?._portOverrideForTesting,
    });

    return res.status(202).json({
      success: true,
      investigationId: id,
      status: 'processing',
    });
  } catch (err) {
    next(err);
  }
}

/**
 * GET /api/investigations/:id
 * Fetches an investigation by ID (polled every 1.2s by the frontend)
 */
export async function getInvestigation(req, res, next) {
  try {
    const { id } = req.params;
    const record = await repository.getInvestigation(id);

    if (!record) {
      return sendError(res, {
        code: ERROR_CODES.NOT_FOUND,
        message: `Investigation with ID '${id}' was not found.`,
      }, 404);
    }

    // Build the report payload matching the contract
    const report = {
      id: record.id,
      type: record.type,
      status: record.status,
      createdAt: record.createdAt,
      completedAt: record.completedAt || null,
      demo: false,
      target: record.target,
      steps: record.steps,
      checks: record.checks || [],
      ...(record.report || {}),
    };

    if (record.status === 'completed') {
      report.classification = record.classification || record.report?.classification;
      report.confidence = record.confidence || record.report?.confidence;
      report.heuristicScore = record.heuristicScore ?? record.report?.heuristicScore ?? record.score;
      report.coverage = record.coverage || record.report?.coverage;
      report.findings = record.findings || record.report?.findings || [];
      report.redirectChain = record.redirectChain || record.report?.redirectChain || [];
      report.tls = record.tls || record.report?.tls;
      report.securityHeaders = record.securityHeaders || record.report?.securityHeaders;
      report.explanation = record.explanation || record.report?.explanation;
      report.recommendations = record.recommendations || record.report?.recommendations || [];
      report.limitations = record.limitations || record.report?.limitations || [];
      report.registry = record.registry || record.report?.registry || { status: 'not_registered' };
      if (record.domainAnalysis || record.report?.domainAnalysis) {
        report.domainAnalysis = record.domainAnalysis || record.report?.domainAnalysis;
      }
      report.analyzedAt = record.analyzedAt || record.completedAt;
    }

    if (record.status === 'failed' && record.error) {
      report.error = record.error;
    }

    return sendSuccess(res, { report });
  } catch (err) {
    next(err);
  }
}


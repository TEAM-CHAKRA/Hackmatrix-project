import { repository } from '../store/repository.js';
import { runUrlChecks } from '../services/urlChecks.js';
import { analyzeMessage } from '../services/messageAnalyzer.js';
import { buildReport } from '../services/reportBuilder.js';
import { DEFAULT_STEPS } from '../config/constants.js';

export const DEFAULT_MAX_CONCURRENCY = 5;
export const DEFAULT_JOB_TIMEOUT_MS = 60000;

/**
 * In-Memory Asynchronous Investigation Queue and Worker
 * 
 * Complies with Phase 6:
 * - Concurrency limited (default 5 concurrent jobs) with FIFO ordering.
 * - Overall job timeout (default 60s) with clean timeout termination.
 * - Live stepper progress and live partial checks written to repository.
 * - Safe error handling (never crashes process, no unhandled rejections).
 * - Zero memory leaks (finished jobs pruned immediately).
 */
export class InvestigationQueue {
  constructor(options = {}) {
    this.maxConcurrency = options.maxConcurrency || DEFAULT_MAX_CONCURRENCY;
    this.timeoutMs = options.timeoutMs || DEFAULT_JOB_TIMEOUT_MS;
    this.fetchFn = options.fetchFn;

    this.queue = [];
    this.running = new Set();
    this._drainResolvers = [];
  }

  /**
   * Enqueue a new investigation job.
   * 
   * @param {object} job
   * @param {string} job.investigationId
   * @param {'url' | 'message'} job.type
   * @param {string} [job.target]
   * @param {string} [job.content]
   * @param {string} [job.validatedIp]
   * @param {number} [job.family]
   * @param {string[]} [job.addresses]
   * @param {Function} [job.resolver]
   * @param {Function} [job.fetchFn]
   * @param {Function} [job.requestFn]
   * @param {Function} [job.tlsConnectFn]
   * @param {number} [job.timeoutMs]
   */
  enqueue(job) {
    if (!job || !job.investigationId) {
      throw new Error('Investigation job requires an investigationId');
    }

    this.queue.push(job);
    process.nextTick(() => this._processNext());
    return job;
  }

  /**
   * Wait until all enqueued and currently executing jobs have finished.
   * Highly useful for testing.
   */
  async drain() {
    if (this.queue.length === 0 && this.running.size === 0) {
      return;
    }
    return new Promise((resolve) => {
      this._drainResolvers.push(resolve);
    });
  }

  /**
   * Clear pending queue (e.g. between tests)
   */
  clear() {
    this.queue = [];
  }

  _notifyDrain() {
    if (this.queue.length === 0 && this.running.size === 0) {
      while (this._drainResolvers.length > 0) {
        const resolve = this._drainResolvers.shift();
        try {
          resolve();
        } catch {
          // ignore
        }
      }
    }
  }

  _processNext() {
    while (this.running.size < this.maxConcurrency && this.queue.length > 0) {
      const job = this.queue.shift();
      this.running.add(job.investigationId);

      this._runJob(job)
        .catch(() => {
          // _runJob internally catches, but guard against unhandled rejection
        })
        .finally(() => {
          this.running.delete(job.investigationId);
          this._notifyDrain();
          this._processNext();
        });
    }
    this._notifyDrain();
  }

  async _runJob(job) {
    const jobTimeoutMs = job.timeoutMs || this.timeoutMs;
    const abortController = new AbortController();
    job.abortController = abortController;
    job.signal = abortController.signal;
    job.isCancelled = false;

    let timer = null;

    const timeoutPromise = new Promise((_, reject) => {
      timer = setTimeout(() => {
        job.isCancelled = true;
        abortController.abort();
        const timeoutErr = new Error('Investigation timed out after 60 seconds.');
        timeoutErr.code = 'JOB_TIMEOUT';
        reject(timeoutErr);
      }, jobTimeoutMs);
      if (typeof timer.unref === 'function') timer.unref();
    });

    try {
      await Promise.race([
        this._executeInvestigation(job),
        timeoutPromise,
      ]);
    } catch (err) {
      await this._handleJobFailure(job, err);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async _executeInvestigation(job) {
    const { investigationId, type } = job;

    // Helper: prevent late partial writes if job was cancelled or timed out
    const safeUpdate = async (updates) => {
      if (job.isCancelled || job.signal?.aborted) {
        return null;
      }
      const current = await repository.getInvestigation(investigationId);
      if (!current || current.status === 'failed' || current.status === 'completed') {
        job.isCancelled = true;
        return null;
      }
      return repository.updateInvestigation(investigationId, updates);
    };

    // -----------------------------------------------------------------------
    // Message-Type Investigations (Phase 4 Hook)
    // -----------------------------------------------------------------------
    if (type === 'message') {
      await this._executeMessageInvestigation(job, safeUpdate);
      return;
    }

    // -----------------------------------------------------------------------
    // URL-Type Investigations
    // -----------------------------------------------------------------------
    const record = await repository.getInvestigation(investigationId);
    let steps = (record?.steps || DEFAULT_STEPS.url).map((s) => ({ ...s }));

    // Step 2: Investigation - Mark running while parsing and preparing target
    steps = steps.map((s) => (s.key === 'investigation' ? { ...s, status: 'running' } : s));
    await safeUpdate({ steps });

    // Target is validated and prepared
    steps = steps.map((s) => (s.key === 'investigation' ? { ...s, status: 'completed' } : s));
    // Threat intel and TLS security steps enter running state as parallel checks begin
    steps = steps.map((s) =>
      s.key === 'threat_intel' || s.key === 'tls_security' ? { ...s, status: 'running' } : s
    );
    await safeUpdate({ steps });

    // Track real-time checks completion
    const checksMap = new Map();

    const onCheckComplete = async (checkItem) => {
      if (job.isCancelled || job.signal?.aborted) return;

      checksMap.set(checkItem.id, checkItem);
      const currentChecks = Array.from(checksMap.values());

      let stepsUpdated = false;

      // threat_intel: completed when gsb and urlhaus have finished
      if (checksMap.has('gsb') && checksMap.has('urlhaus')) {
        const tiStep = steps.find((s) => s.key === 'threat_intel');
        if (tiStep && tiStep.status !== 'completed') {
          tiStep.status = 'completed';
          stepsUpdated = true;
        }
      }

      // tls_security: completed when tls, ct, and headers have finished
      if (checksMap.has('tls') && checksMap.has('ct') && checksMap.has('headers')) {
        const tlsStep = steps.find((s) => s.key === 'tls_security');
        if (tlsStep && tlsStep.status !== 'completed') {
          tlsStep.status = 'completed';
          stepsUpdated = true;
        }
      }

      // Live update repository so polling immediately shows partial checks
      await safeUpdate({
        checks: currentChecks,
        steps: [...steps],
      });
    };

    // Run parallel checks (reusing validated IPs without re-resolving)
    const checkResults = await runUrlChecks({
      url: job.target,
      resolver: job.resolver,
      fetchFn: job.fetchFn || this.fetchFn || globalThis.fetch,
      requestFn: job.requestFn,
      tlsConnectFn: job.tlsConnectFn,
      tlsTimeoutMs: job.tlsTimeoutMs,
      preValidatedIp: job.validatedIp,
      preValidatedFamily: job.family,
      preValidatedAddresses: job.addresses,
      onCheckComplete,
      signal: job.signal,
      _dangerouslyAllowLocalhostForTesting: job._dangerouslyAllowLocalhostForTesting,
      _portOverrideForTesting: job._portOverrideForTesting,
    });

    if (job.isCancelled || job.signal?.aborted) return;

    // Ensure threat_intel and tls_security steps are marked completed
    steps = steps.map((s) =>
      s.key === 'threat_intel' || s.key === 'tls_security' ? { ...s, status: 'completed' } : s
    );

    // Step 5: Risk Report - Running
    steps = steps.map((s) => (s.key === 'risk_report' ? { ...s, status: 'running' } : s));
    await safeUpdate({
      steps,
      checks: checkResults.checks,
    });

    if (job.isCancelled || job.signal?.aborted) return;

    // Build the final evaluation report
    const report = await buildReport({
      id: investigationId,
      type: 'url',
      target: checkResults.target,
      checks: checkResults.checks,
      findings: checkResults.findings,
      tls: checkResults.tls,
      securityHeaders: checkResults.securityHeaders,
      redirectChain: checkResults.redirectChain,
      domainAnalysis: checkResults.domainAnalysis,
      fetchFn: job.fetchFn || this.fetchFn || globalThis.fetch,
    });

    if (job.isCancelled || job.signal?.aborted) return;

    // Step 5: Risk Report - Completed
    steps = steps.map((s) => (s.key === 'risk_report' ? { ...s, status: 'completed' } : s));

    const completedAt = new Date().toISOString();

    // Persist full report onto repository record
    await safeUpdate({
      status: 'completed',
      completedAt,
      analyzedAt: completedAt,
      classification: report.classification,
      confidence: report.confidence,
      heuristicScore: report.heuristicScore,
      score: report.score,
      scoreBreakdown: report.scoreBreakdown,
      coverage: report.coverage,
      findings: report.findings.map((f) => ({
        ...f,
        source: f.source || 'Threat Intelligence analysis',
      })),
      explanation: report.explanation,
      recommendations: report.recommendations,
      limitations: report.limitations,
      registry: report.registry || { status: 'not_registered' },
      redirectChain: report.redirectChain,
      tls: report.tls,
      securityHeaders: report.securityHeaders,
      domainAnalysis: report.domainAnalysis,
      checks: checkResults.checks,
      steps,
      report, // preserve complete report object for GET /api/investigations/:id
    });
  }

  /**
   * Phase 4 — message pipeline: indicators + tactics → threat intel on links →
   * link checks → scoring/report. The tls_security step is "skipped" for
   * messages (amendment 16). The raw text is dropped from the record once the
   * analysis is finished; only derived data is kept.
   */
  async _executeMessageInvestigation(job, safeUpdate) {
    const { investigationId } = job;
    const record = await repository.getInvestigation(investigationId);
    let steps = (record?.steps || DEFAULT_STEPS.message).map((s) => ({ ...s }));
    const setStep = (key, status) => {
      steps = steps.map((s) => (s.key === key ? { ...s, status } : s));
    };

    setStep('investigation', 'running');
    setStep('tls_security', 'skipped');
    await safeUpdate({ steps });

    const checksMap = new Map();
    const onCheckComplete = async (check) => {
      if (job.isCancelled || job.signal?.aborted) return;
      checksMap.set(check.id, check);
      if (check.id === 'tactics') {
        setStep('investigation', 'completed');
        setStep('threat_intel', 'running');
      }
      if (check.id === 'threat_intel') setStep('threat_intel', 'completed');
      await safeUpdate({ checks: Array.from(checksMap.values()), steps: [...steps] });
    };

    const content = job.content ?? record?.targetRaw ?? '';
    const analysis = await analyzeMessage({
      content,
      fetchFn: job.fetchFn || this.fetchFn || globalThis.fetch,
      onCheckComplete,
    });
    if (job.isCancelled || job.signal?.aborted) return;

    setStep('investigation', 'completed');
    setStep('threat_intel', 'completed');
    setStep('risk_report', 'running');
    await safeUpdate({ steps, checks: analysis.checks });

    const report = await buildReport({
      id: investigationId,
      type: 'message',
      target: { display: 'Submitted message' },
      checks: analysis.checks,
      findings: [],
      message: analysis.message,
      fetchFn: job.fetchFn || this.fetchFn || globalThis.fetch,
    });
    if (job.isCancelled || job.signal?.aborted) return;

    setStep('risk_report', 'completed');
    const completedAt = new Date().toISOString();
    await safeUpdate({
      status: 'completed',
      completedAt,
      analyzedAt: completedAt,
      classification: report.classification,
      confidence: report.confidence,
      heuristicScore: report.heuristicScore,
      score: report.score,
      scoreBreakdown: report.scoreBreakdown,
      coverage: report.coverage,
      findings: report.findings,
      explanation: report.explanation,
      recommendations: report.recommendations,
      limitations: report.limitations,
      registry: report.registry || { status: 'not_registered' },
      message: report.message,
      checks: analysis.checks,
      steps,
      targetRaw: null, // privacy: keep only derived data
      report,
    });
  }

  async _handleJobFailure(job, err) {
    job.isCancelled = true;
    if (job.abortController && !job.signal?.aborted) {
      job.abortController.abort();
    }

    try {
      const record = await repository.getInvestigation(job.investigationId);
      // If already terminal (failed or completed), do NOT overwrite
      if (record?.status === 'failed' || record?.status === 'completed') {
        return;
      }

      const currentSteps = (record?.steps || DEFAULT_STEPS[job.type] || DEFAULT_STEPS.url).map((s) => ({ ...s }));

      let runningMarkedFailed = false;
      const updatedSteps = currentSteps.map((step) => {
        if (step.status === 'running') {
          runningMarkedFailed = true;
          return { ...step, status: 'failed' };
        }
        if (step.status === 'pending') {
          return { ...step, status: 'skipped' };
        }
        return step;
      });

      // If no step was running when error hit, mark the first incomplete step failed
      if (!runningMarkedFailed) {
        for (const step of updatedSteps) {
          if (step.status !== 'completed') {
            step.status = 'failed';
            break;
          }
        }
      }

      // Short, safe error message without leaking stack traces or internal paths
      let safeMessage = 'Investigation processing failed. The target could not be assessed.';
      if (err.code === 'JOB_TIMEOUT' || err.message?.includes('timed out')) {
        safeMessage = 'Investigation timed out after 60 seconds.';
      } else if (err.isSafeMessage) {
        safeMessage = err.message;
      }

      await repository.updateInvestigation(job.investigationId, {
        status: 'failed',
        error: {
          message: safeMessage,
        },
        steps: updatedSteps,
        completedAt: new Date().toISOString(),
      });
    } catch {
      // Failure handler must never crash the queue
    }
  }
}

// Export singleton instance used throughout application
export const investigationQueue = new InvestigationQueue();


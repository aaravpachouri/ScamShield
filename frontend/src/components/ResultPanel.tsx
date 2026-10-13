import { useState, type CSSProperties } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  CircleHelp,
  Copy,
  Fingerprint,
  Link2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from 'lucide-react';
import type { AnalyzeResponse, ScamAnalysis } from '../types';

interface Props {
  response: AnalyzeResponse;
  onCopy?: (message: string) => void;
}

function scoreOf(result: ScamAnalysis): number | null {
  return typeof result.final_score === 'number' ? result.final_score : null;
}

export default function ResultPanel({ response, onCopy }: Props) {
  const [technicalOpen, setTechnicalOpen] = useState(false);
  const result = response.result;
  const score = scoreOf(result);
  const level = result.final_level ?? 'UNCLASSIFIED';
  const isHigh = level.toLowerCase().includes('high');
  const isSuspicious = level.toLowerCase().includes('suspicious');
  const tone = isHigh ? 'danger' : isSuspicious ? 'warning' : 'safe';
  const Icon = isHigh ? ShieldAlert : isSuspicious ? AlertTriangle : ShieldCheck;
  const ai = result.ai_analysis;
  const aiResult = ai?.result;
  const url = result.url_analysis;
  const aiReturned = Boolean(ai?.available && aiResult);
  const aiDiagnostic = ai?.error || ai?.status || 'No AI diagnostic returned';

  async function copyReport() {
    const report = [
      `ScamShield analysis: ${level}${score === null ? '' : ` (${score}/100)`}`,
      `Category: ${result.final_category ?? 'Not available'}`,
      '',
      'Evidence:',
      ...(result.reasons ?? []).map((item) => `- ${item}`),
      '',
      'Recommended actions:',
      ...(result.actions ?? []).map((item) => `- ${item}`),
    ].join('\n');

    try {
      await navigator.clipboard.writeText(report);
      onCopy?.('Analysis report copied');
    } catch {
      onCopy?.('Clipboard access was blocked by this browser.');
    }
  }

  return (
    <motion.section
      className="result-panel"
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.42 }}
      aria-live="polite"
    >
      <div className="result-panel-head">
        <div>
          <div className="eyebrow">ANALYSIS COMPLETE</div>
          <h3>Your assessment</h3>
        </div>
        <button className="secondary-button compact" type="button" onClick={copyReport}>
          <Copy size={14} /> Copy report
        </button>
      </div>

      <div className={`risk-hero risk-${tone}`}>
        <div className="risk-ring" style={{ '--risk-progress': `${score ?? 0}%` } as CSSProperties}>
          <div className="risk-ring-inner">
            <strong>{score === null ? '—' : score}</strong>
            <span>/ 100</span>
          </div>
        </div>
        <div className="risk-summary">
          <div className="risk-kicker"><Icon size={16} /> {level}</div>
          <h4>{result.final_category ?? 'Category unavailable'}</h4>
          <p>
            {isHigh
              ? 'The submitted content contains multiple warning signs. Treat the request cautiously and verify it through an independent channel.'
              : isSuspicious
                ? 'Some warning signs were identified. Do not act until you have independently verified the sender and destination.'
                : 'No strong warning signals were identified by the current prototype. This does not guarantee the content is safe.'}
          </p>
          <div className="risk-score-note">
            <CircleHelp size={13} /> Prototype heuristic score—not a probability of fraud.
          </div>
        </div>
      </div>

      <div className="result-columns">
        <div className="result-column">
          <div className="result-section-label"><Fingerprint size={15} /> Why it was flagged</div>
          {(result.reasons?.length ? result.reasons : ['No rule-based explanation was returned.']).map((reason, index) => (
            <motion.div
              key={`${index}-${reason}`}
              className="evidence-line"
              initial={{ opacity: 0, x: -7 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.045 }}
            >
              <span className="evidence-check"><CheckCircle2 size={13} /></span>
              <span>{reason}</span>
            </motion.div>
          ))}
          {url?.success && (
            <div className="url-evidence-box">
              <div className="url-evidence-top">
                <Link2 size={15} /><span>URL structure check</span>
                <b>{typeof url.score === 'number' ? `${url.score}/100` : 'Analysed'}</b>
              </div>
              <div className="url-domain">{url.domain ?? url.url ?? 'URL detected'}</div>
              {(url.reasons ?? []).map((reason, index) => (
                <div className="url-evidence-reason" key={`${index}-${reason}`}>{reason}</div>
              ))}
            </div>
          )}
        </div>

        <div className="result-column action-column">
          <div className="result-section-label"><ShieldCheck size={15} /> Suggested next steps</div>
          {(result.actions?.length ? result.actions : ['Verify the sender independently before taking action.']).map((action, index) => (
            <div className="action-line" key={`${index}-${action}`}>
              <span>{String(index + 1).padStart(2, '0')}</span><p>{action}</p>
            </div>
          ))}
          {aiResult?.recommended_action && (
            <div className="ai-advice">
              <div className="ai-advice-label"><Sparkles size={13} /> AI model suggestion</div>
              <p>{aiResult.recommended_action}</p>
            </div>
          )}
        </div>
      </div>

      <div className="ai-summary-row">
        <div className="ai-orb"><Sparkles size={18} /></div>
        <div className="ai-summary-copy">
          <b>Semantic analysis</b>
          <span>
            {aiReturned
              ? `${aiResult.scam_type ?? 'Assessment returned'} · ${aiResult.manipulation_tactics?.join(' / ') || 'No tactics listed'}`
              : 'Unavailable for this request. Rule-based evidence is shown where available.'}
          </span>
        </div>
        <span
          className={`inline-status ${aiReturned ? 'status-ready' : 'status-muted'}`}
          title={aiDiagnostic}
        >
          <i />
          {aiReturned ? 'Returned' : `Unavailable${ai?.status ? ` · ${ai.status}` : ''}`}
        </span>
      </div>

      {aiResult?.explanation && <p className="ai-explanation">{aiResult.explanation}</p>}
      {!aiReturned && (ai?.error || ai?.status) && (
        <p className="ai-explanation" role="status">
          AI diagnostic: {ai.error ?? ai.status}
        </p>
      )}

      {response.ocr_text && (
        <details className="ocr-disclosure">
          <summary>View text extracted from screenshot</summary>
          <pre>{response.ocr_text}</pre>
        </details>
      )}

      <button
        className={`technical-toggle ${technicalOpen ? 'open' : ''}`}
        type="button"
        onClick={() => setTechnicalOpen((value) => !value)}
        aria-expanded={technicalOpen}
      >
        <span><Fingerprint size={15} /> Inspect technical evidence</span>
        <ChevronDown size={16} />
      </button>

      <AnimatePresence initial={false}>
        {technicalOpen && (
          <motion.div
            className="technical-details"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.24 }}
          >
            <div className="tech-metrics">
              <div><span>Rule score</span><b>{typeof result.rule_score === 'number' ? `${result.rule_score}/100` : 'Not returned'}</b></div>
              <div><span>AI model</span><b>{ai?.model ?? 'Not reported'}</b></div>
              <div><span>URL score</span><b>{typeof url?.score === 'number' ? `${url.score}/100` : 'No URL score'}</b></div>
            </div>
            <div className="fusion-list">
              {(result.fusion_evidence ?? []).length
                ? result.fusion_evidence?.map((item, index) => (
                    <div key={`${index}-${item}`}><span>{String(index + 1).padStart(2, '0')}</span>{item}</div>
                  ))
                : <p>No fusion evidence was returned by the backend.</p>}
            </div>
            <div className="technical-caveat">
              <AlertTriangle size={14} /> These prototype scores use hand-set rules and fusion weights. They have not yet been statistically calibrated against a representative labelled dataset.
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="result-safe-note">
        <ShieldCheck size={15} />
        <span>Never share an OTP or password. A low-risk result is not a guarantee of safety.</span>
        <a href="#evaluation">Evaluation notes <ArrowUpRight size={12} /></a>
      </div>
    </motion.section>
  );
}

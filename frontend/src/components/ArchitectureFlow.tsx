import { useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowDown, ArrowRight, Braces, CheckCircle2, CircleDot, Link2, ScanSearch, ShieldCheck, Sparkles } from 'lucide-react';

const stages = [
  { id: 'input', number: '01', title: 'Input', subtitle: 'Message · Link · Screenshot', icon: Braces, detail: 'A visitor submits message text, a standalone URL, or an image. Screenshot text is extracted by local OCR when the optional OCR dependencies are installed.' },
  { id: 'rules', number: '02', title: 'Rule signals', subtitle: 'Transparent pattern checks', icon: ShieldCheck, detail: 'The current rule engine looks for indicators such as urgency, credential requests, threats, financial terms, impersonation-related wording, and URLs. These are signals—not proof.' },
  { id: 'url', number: '03', title: 'URL analysis', subtitle: 'Structure and hostname', icon: Link2, detail: 'When a URL is present, ScamShield checks selected structural patterns such as suspicious terms, shorteners, unusual host forms, and possible brand impersonation. It does not currently guarantee reputation or destination safety.' },
  { id: 'llm', number: '04', title: 'Local LLM', subtitle: 'Llama 3.2 via Ollama', icon: Sparkles, detail: 'The local model returns a structured semantic assessment, including a likely-scam flag, scam type, tactics, explanation, and recommended action. AI availability depends on the local Ollama setup.' },
  { id: 'fusion', number: '05', title: 'Evidence fusion', subtitle: 'Prototype score + guidance', icon: ScanSearch, detail: 'The current fusion layer combines rule, URL, and AI signals using prototype heuristics. Its score is not a calibrated probability and needs systematic evaluation before high-stakes use.' },
];

export default function ArchitectureFlow() {
  const [selected, setSelected] = useState(stages[0].id);
  const active = stages.find((stage) => stage.id === selected) ?? stages[0];
  return (
    <div className="architecture-shell">
      <div className="architecture-rail" aria-label="ScamShield processing stages">
        {stages.map((stage, index) => {
          const Icon = stage.icon;
          const isActive = stage.id === selected;
          return (
            <div className="architecture-stage-wrap" key={stage.id}>
              <motion.button
                type="button"
                className={`architecture-stage ${isActive ? 'is-active' : ''}`}
                onClick={() => setSelected(stage.id)}
                whileHover={{ y: -3 }}
                whileTap={{ scale: 0.985 }}
                aria-pressed={isActive}
              >
                <span className="architecture-stage-top"><span>{stage.number}</span><Icon size={18} /></span>
                <strong>{stage.title}</strong>
                <small>{stage.subtitle}</small>
                <span className="architecture-select">{isActive ? 'Selected' : 'Inspect stage'}</span>
              </motion.button>
              {index < stages.length - 1 && <div className="architecture-connector"><span /><ArrowRight size={15} /></div>}
            </div>
          );
        })}
      </div>
      <motion.div className="architecture-detail" key={active.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.25 }}>
        <div className="architecture-detail-icon"><active.icon size={19} /></div>
        <div className="architecture-detail-copy">
          <div className="eyebrow">STAGE {active.number} / PROCESS DETAIL</div>
          <h3>{active.title}</h3>
          <p>{active.detail}</p>
        </div>
        <div className="architecture-detail-status"><CircleDot size={14} /> Pipeline component</div>
      </motion.div>
      <div className="architecture-mobile-hint"><ArrowDown size={14} /> Select a stage to inspect its role</div>
      <div className="architecture-disclaimer"><CheckCircle2 size={14} /> This diagram describes the application's current processing flow, not undocumented internal neural-network internals.</div>
    </div>
  );
}

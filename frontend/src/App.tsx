import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, motion, useReducedMotion, useScroll } from 'framer-motion';
import {
  ArrowDown, ArrowRight, ArrowUpRight, BookOpen, Check, CheckCircle2, ChevronDown,
  CircleHelp, CloudOff, Code2, ExternalLink, Eye, Fingerprint, Github, Globe2,
  Layers3, Link2, LockKeyhole, Menu, MessageSquareText, MousePointer2, ScanLine,
  ShieldCheck, ShieldHalf, Sparkles, Workflow, X, Zap,
} from 'lucide-react';
import CoreVisual from './components/CoreVisual';
import ArchitectureFlow from './components/ArchitectureFlow';
import Playground from './components/Playground';
import CodeExample from './components/CodeExample';
import { getHealth } from './lib/api';
import type { ApiHealth, AnalyzeResponse, SourceMode } from './types';
import {
  HistoryPanel,
  KnowledgeLibrary,
  type SavedAnalysis
} from './components/CommunityFeatures';

import ScamSchool from './components/ScamSchool';

const navigation = [
  { label: 'Overview', id: 'overview' },
  { label: 'Playground', id: 'playground' },
  { label: 'History', id: 'history' },
  { label: 'Scam School', id: 'scam-school' },
  { label: 'Knowledge', id: 'knowledge' },
  { label: 'Developers', id: 'developers' },
];

const capabilityData: {
  id: string; index: string; tab: string; title: string; description: string; detail: string;
  bullets: string[]; mode: SourceMode; sample: string; icon: typeof MessageSquareText;
}[] = [
  {
    id: 'message', index: '01', tab: 'Message analysis', title: 'Read the message behind the message.',
    description: 'Look for urgency, requests for sensitive details, threats, financial language, and references that may indicate impersonation.',
    detail: 'Current approach · transparent rule signals + local semantic assessment',
    bullets: ['Urgency and fear tactics', 'OTP, password, and account-action requests', 'AI-generated explanation when local Ollama is available'],
    mode: 'Message', icon: MessageSquareText,
    sample: 'Your bank account will be blocked today. Verify your KYC immediately and enter your OTP: https://sbi-login-verify.example.com/kyc',
  },
  {
    id: 'link', index: '02', tab: 'URL inspection', title: 'Inspect the address, not just the promise.',
    description: 'Check selected structural warning signs in a URL, including hostname patterns, shorteners, suspicious terms, and possible brand impersonation.',
    detail: 'Current approach · heuristic URL structure analysis',
    bullets: ['Hostname and subdomain patterns', 'Selected look-alike brand indicators', 'Signals are not a reputation lookup or safety guarantee'],
    mode: 'Link', icon: Link2,
    sample: 'https://sbi-login-verify.example.com/kyc',
  },
  {
    id: 'screenshot', index: '03', tab: 'Screenshot OCR', title: 'Check the screenshot you were sent.',
    description: 'Submit a screenshot of a message and, when local OCR dependencies are available, extract its readable text before analysis.',
    detail: 'Current approach · optional local Tesseract OCR + same analysis endpoint',
    bullets: ['PNG, JPG, and WEBP supported by the API adapter', 'OCR depends on Pillow, pytesseract, and Tesseract', 'Review extracted text before relying on the assessment'],
    mode: 'Screenshot', icon: ScanLine,
    sample: '',
  },
];

const specRows = [
  ['Product type', 'Experimental message and URL risk-analysis tool'],
  ['Semantic model', 'Llama 3.2 through a local Ollama runtime'],
  ['Decision layer', 'Transparent rule engine + prototype evidence fusion'],
  ['URL analysis', 'Heuristic hostname and URL-structure checks'],
  ['Screenshot input', 'Optional local OCR through Tesseract'],
  ['API layer', 'FastAPI adapter · local development endpoint'],
  ['Model weights / exact build', 'Depends on the local Ollama installation'],
  ['Context length / parameter details', 'Not published for this application build'],
  ['License', 'Not yet published for the ScamShield application'],
];

const benchmarkRows = [
  { metric: 'Precision / recall', status: 'Not yet published', copy: 'Requires a labelled, held-out set of legitimate and scam-like messages.' },
  { metric: 'False-positive rate', status: 'Not yet measured', copy: 'Critical to avoid flagging ordinary banking, delivery, and OTP notifications incorrectly.' },
  { metric: 'False-negative rate', status: 'Not yet measured', copy: 'Needs diverse scam types, languages, and obfuscated examples.' },
  { metric: 'URL detection quality', status: 'Evaluation planned', copy: 'Evaluate on legitimate domains, known phishing indicators, shorteners, and look-alike hostnames.' },
];

const roadmap = [
  { state: 'current', label: 'Prototype implemented', title: 'Local analysis pipeline', copy: 'Rule signals, URL heuristics, local Llama assessment, and a prototype fusion score are implemented in the current codebase.' },
  { state: 'current', label: 'Adapter available', title: 'Local API + screenshot route', copy: 'FastAPI endpoints cover health, text/URL analysis, and screenshot OCR; OCR requires local system dependencies.' },
  { state: 'next', label: 'Next research milestone', title: 'Build a representative evaluation set', copy: 'Label legitimate and suspicious messages, define splits, and report precision, recall, false positives, and false negatives.' },
  { state: 'planned', label: 'Planned', title: 'Calibrated scoring and robustness', copy: 'Replace hand-set fusion weights with evidence-based calibration and test English, Hindi, Hinglish, and obfuscated text.' },
];

function scrollTo(id: string, reducedMotion: boolean | null) {
  document.getElementById(id)?.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
}

function Reveal({ children, className = '', delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  const reduceMotion = useReducedMotion();
  return (
    <motion.div
      className={className}
      initial={reduceMotion ? false : { opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.12 }}
      transition={{ duration: reduceMotion ? 0 : 0.62, delay: reduceMotion ? 0 : delay, ease: [0.2, 0.75, 0.25, 1] }}
    >{children}</motion.div>
  );
}

function SectionHeading({ index, eyebrow, title, copy }: { index: string; eyebrow: string; title: string; copy: string }) {
  return (
    <div className="section-heading">
      <div className="section-index"><span>{index}</span><i /></div>
      <div className="section-heading-copy"><div className="eyebrow">{eyebrow}</div><h2>{title}</h2><p>{copy}</p></div>
    </div>
  );
}

function App() {
  const reduceMotion = useReducedMotion();
  const { scrollYProgress } = useScroll();
  const [apiState, setApiState] = useState<'checking' | 'online' | 'offline'>('checking');
  const [apiHealth, setApiHealth] = useState<ApiHealth | null>(null);
  const [activeNav, setActiveNav] = useState('overview');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [capability, setCapability] = useState(capabilityData[0].id);
  const [playgroundSeed, setPlaygroundSeed] = useState<{ mode: SourceMode; text: string; trigger: number }>({ mode: 'Message', text: '', trigger: 0 });
  const [toast, setToast] = useState('');
  const [savedAnalyses, setSavedAnalyses] = useState<SavedAnalysis[]>(() => {
    try { const raw = localStorage.getItem('scamshield.history.v1'); return raw ? JSON.parse(raw) as SavedAnalysis[] : []; } catch { return []; }
  });
  const toastTimer = useRef<number | null>(null);

  const refreshHealth = useCallback(async () => {
    try {
      const health = await getHealth();
      setApiHealth(health);
      setApiState(health.status === 'ok' ? 'online' : 'offline');
    } catch {
      setApiHealth(null);
      setApiState('offline');
    }
  }, []);

  useEffect(() => {
    void refreshHealth();
    const timer = window.setInterval(() => void refreshHealth(), 25_000);
    return () => window.clearInterval(timer);
  }, [refreshHealth]);

  useEffect(() => {
    const elements = navigation.map((item) => document.getElementById(item.id)).filter(Boolean) as HTMLElement[];
    if (!('IntersectionObserver' in window) || !elements.length) return;
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (visible) setActiveNav(visible.target.id);
    }, { rootMargin: '-28% 0px -56% 0px', threshold: [0.05, 0.2, 0.45] });
    elements.forEach((element) => observer.observe(element));
    return () => observer.disconnect();
  }, []);

  useEffect(() => () => { if (toastTimer.current) window.clearTimeout(toastTimer.current); }, []);

  useEffect(() => {
    try { localStorage.setItem('scamshield.history.v1', JSON.stringify(savedAnalyses.slice(0, 50))); } catch { /* storage may be disabled or full */ }
  }, [savedAnalyses]);

  const saveAnalysis = useCallback((response: AnalyzeResponse) => {
    const result = response.result;
    const entry: SavedAnalysis = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      createdAt: new Date().toISOString(),
      text: response.analyzed_text ?? result.message ?? '',
      mode: response.source_mode ?? result.source_mode ?? 'Message',
      score: result.final_score ?? result.rule_score ?? 0,
      level: result.final_level ?? result.rule_level ?? 'UNASSESSED',
      category: result.final_category ?? result.rule_category ?? 'Unknown category',
      response,
    };
    setSavedAnalyses(current => [entry, ...current.filter(item => item.text !== entry.text)].slice(0, 50));
  }, []);

  const deleteAnalysis = useCallback((id: string) => setSavedAnalyses(current => current.filter(item => item.id !== id)), []);
  const clearHistory = useCallback(() => setSavedAnalyses([]), []);

  const showToast = useCallback((message: string) => {
    setToast(message);
    if (toastTimer.current) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(''), 3000);
  }, []);

  function startPlayground(mode?: SourceMode, text?: string) {
    if (mode) {
      setPlaygroundSeed((current) => ({ mode, text: text ?? '', trigger: current.trigger + 1 }));
    }
    scrollTo('playground', reduceMotion);
    setMobileMenuOpen(false);
  }

  const selectedCapability = capabilityData.find((item) => item.id === capability) ?? capabilityData[0];
  const navApiLabel = apiState === 'online' ? 'API REACHABLE' : apiState === 'offline' ? 'API OFFLINE' : 'CHECKING API';

  return (
    <div className="site-shell">
      <motion.div className="scroll-progress" style={{ scaleX: scrollYProgress }} />
      <div className="ambient ambient-one" /><div className="ambient ambient-two" /><div className="site-grid" />
      <header className="site-header">
        <a className="brand-lockup" href="#top" onClick={(event) => { event.preventDefault(); scrollTo('top', reduceMotion); }} aria-label="ScamShield home">
          <span className="brand-symbol"><ShieldCheck size={22} strokeWidth={1.7} /></span>
          <span className="brand-wordmark"><b>ScamShield</b><small>PERSONAL CYBER SAFETY</small></span>
        </a>
        <nav className={`desktop-nav ${mobileMenuOpen ? 'mobile-open' : ''}`} aria-label="Main navigation">
          {navigation.map((item) => <a key={item.id} className={activeNav === item.id ? 'active' : ''} href={`#${item.id}`} onClick={(event) => { event.preventDefault(); setActiveNav(item.id); scrollTo(item.id, reduceMotion); setMobileMenuOpen(false); }}>{item.label}</a>)}
        </nav>
        <div className="header-actions">
          <span className={`header-api-status ${apiState}`}><i />{navApiLabel}</span>
          <button className="mobile-menu-button" type="button" aria-label={mobileMenuOpen ? 'Close navigation' : 'Open navigation'} aria-expanded={mobileMenuOpen} onClick={() => setMobileMenuOpen((value) => !value)}>{mobileMenuOpen ? <X size={19} /> : <Menu size={19} />}</button>
          <button className="header-cta" type="button" onClick={() => startPlayground()}>Open playground <ArrowUpRight size={15} /></button>
        </div>
      </header>

      <main id="top">
        <section className="hero-section section-wrap" aria-labelledby="hero-title">
          <div className="hero-copy">
            <motion.div className="hero-overline" initial={reduceMotion ? false : { opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.55 }}><span className="hero-overline-dot" /> EXPERIMENTAL · LOCAL-FIRST ANALYSIS</motion.div>
            <motion.h1 id="hero-title" initial={reduceMotion ? false : { opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.72, delay: 0.08 }}>
              Before you <span className="gradient-word">click,</span><br />know what you’re looking at.
            </motion.h1>
            <motion.p className="hero-description" initial={reduceMotion ? false : { opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.65, delay: 0.2 }}>
              ScamShield inspects suspicious messages and links, explains the warning signs it finds, and suggests a safer next step—without pretending a score can guarantee safety.
            </motion.p>
            <motion.div className="hero-actions" initial={reduceMotion ? false : { opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.3 }}>
              <button className="primary-button" type="button" onClick={() => startPlayground()}><ScanLine size={17} /> Try the analysis workspace <ArrowRight size={16} /></button>
              <button className="secondary-button" type="button" onClick={() => scrollTo('architecture', reduceMotion)}><Workflow size={16} /> Explore the pipeline</button>
            </motion.div>
            <motion.div className="hero-fine-print" initial={reduceMotion ? false : { opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.55 }}><LockKeyhole size={14} /><span>Local API integration · Model availability checked when a request runs</span></motion.div>
            <div className="hero-trace"><span>INPUT</span><i /><span>ANALYSIS</span><i /><span>EVIDENCE</span><i /><span>GUIDANCE</span></div>
          </div>
          <motion.div className="hero-visual-column" initial={reduceMotion ? false : { opacity: 0, scale: 0.94, x: 15 }} animate={{ opacity: 1, scale: 1, x: 0 }} transition={{ duration: 0.9, delay: 0.12 }}>
            <CoreVisual />
            <div className="visual-caption"><span><i /> SIGNAL FIELD / A</span><span>RULES × LOCAL MODEL</span></div>
          </motion.div>
          <button className="scroll-cue" type="button" onClick={() => scrollTo('overview', reduceMotion)}><span>Scroll to explore</span><ArrowDown size={15} /></button>
        </section>

        <div className="product-strip" aria-label="Product approach">
          <div><span className="strip-icon"><MessageSquareText size={16} /></span><span><b>Message signals</b><small>Urgency · sensitive requests</small></span></div>
          <div><span className="strip-icon"><Link2 size={16} /></span><span><b>URL structure</b><small>Hostname · suspicious patterns</small></span></div>
          <div><span className="strip-icon"><Sparkles size={16} /></span><span><b>Local semantic review</b><small>Llama 3.2 via Ollama</small></span></div>
          <div><span className="strip-icon"><ShieldCheck size={16} /></span><span><b>Actionable guidance</b><small>Evidence with limitations</small></span></div>
        </div>

        <section className="section-wrap section-block overview-section" id="overview">
          <SectionHeading index="01" eyebrow="PRODUCT / CAPABILITIES" title="A second opinion, built around evidence." copy="The current prototype combines transparent pattern checks with a local language-model assessment. Each capability is useful on its own—and imperfect on its own." />
          <Reveal className="capability-explorer">
            <div className="capability-list" role="tablist" aria-label="ScamShield capabilities">
              {capabilityData.map((item) => {
                const Icon = item.icon;
                return <button className={`capability-option ${capability === item.id ? 'selected' : ''}`} type="button" key={item.id} role="tab" aria-selected={capability === item.id} onClick={() => setCapability(item.id)}><span className="capability-option-index">{item.index}</span><span className="capability-option-icon"><Icon size={17} /></span><span className="capability-option-text"><b>{item.tab}</b><small>{item.id === 'message' ? 'Text and intent signals' : item.id === 'link' ? 'Hostname and URL patterns' : 'OCR-assisted message input'}</small></span><ArrowUpRight size={16} className="capability-option-arrow" /></button>;
              })}
              <div className="capability-aside-note"><CircleHelp size={15} /><span>Low risk means no strong indicators were found—not that a message is guaranteed safe.</span></div>
            </div>
            <AnimatePresence mode="wait">
              <motion.div key={selectedCapability.id} className="capability-detail" role="tabpanel" initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -8 }} transition={{ duration: 0.22 }}>
                <div className="capability-detail-top"><span className="eyebrow">CAPABILITY {selectedCapability.index}</span><span className="capability-mini-icon"><selectedCapability.icon size={18} /></span></div>
                <h3>{selectedCapability.title}</h3>
                <p>{selectedCapability.description}</p>
                <div className="capability-detail-rule" />
                <div className="eyebrow">WHAT IT CHECKS</div>
                <ul className="check-list">{selectedCapability.bullets.map((bullet) => <li key={bullet}><Check size={14} />{bullet}</li>)}</ul>
                <div className="capability-detail-bottom"><span>{selectedCapability.detail}</span><button className="text-link" type="button" onClick={() => startPlayground(selectedCapability.mode, selectedCapability.sample)}>{selectedCapability.mode === 'Screenshot' ? 'Open screenshot input' : 'Try this mode'} <ArrowRight size={14} /></button></div>
              </motion.div>
            </AnimatePresence>
          </Reveal>
          <div className="overview-note"><span className="note-marker">NOTE</span><p>ScamShield is an experimental analysis aid. It does not currently verify a domain against a complete threat-intelligence feed, establish who sent a message, or replace official fraud-reporting channels.</p></div>
        </section>

        <section className="architecture-section section-block" id="architecture">
          <div className="section-wrap">
            <SectionHeading index="02" eyebrow="UNDER THE SURFACE / PIPELINE" title="Five stages. One explainable assessment." copy="Inspect the current application flow. Select a stage to see what it contributes and where its limits are." />
            <Reveal><ArchitectureFlow /></Reveal>
          </div>
          <div className="architecture-bottom-glow" />
        </section>

        <section className="section-wrap section-block playground-section" id="playground">
          <SectionHeading index="03" eyebrow="INTERACTIVE / PLAYGROUND" title="Bring the message that made you pause." copy="Test the local integration with a message, a URL, or a screenshot. The interface displays the backend's returned result—or a clear error if the service is unavailable." />
          <Reveal><Playground apiOnline={apiState === 'online' ? true : apiState === 'offline' ? false : null} onToast={showToast} onAnalysis={saveAnalysis} seed={playgroundSeed} /></Reveal>
        </section>

        <section className="section-wrap section-block community-section" id="history">
          <SectionHeading index="04" eyebrow="YOUR DEVICE / PRIVATE HISTORY" title="Your checks, easy to find again." copy="Recent analyses are saved only in this browser on this device. Delete individual entries or clear the full history whenever you want." />
          <Reveal><HistoryPanel items={savedAnalyses} onDelete={deleteAnalysis} onClear={clearHistory} onRecheck={(item) => startPlayground(item.mode === 'Screenshot' ? 'Message' : item.mode, item.text)} /></Reveal>
        </section>

        <section className="community-band section-block" id="scam-school">
          <div className="section-wrap">
            <SectionHeading index="05" eyebrow="LEARN BY PLAYING / SCAM SCHOOL" title="Train your instincts, not your anxiety." copy="Practice spotting common warning signs with short scenarios. These are educational examples, not a certification or a guarantee of real-world detection." />
            <Reveal><ScamSchool onToast={showToast} /></Reveal>
          </div>
        </section>

        <section className="section-wrap section-block community-section" id="knowledge">
          <SectionHeading index="06" eyebrow="KNOWLEDGE BASE / DIGITAL SAFETY" title="A practical guide for the moment you feel unsure." copy="Search concise guidance for bank messages, OTPs, delivery fees, job offers, payment requests, and suspicious links." />
          <Reveal><KnowledgeLibrary /></Reveal>
        </section>

        <section className="evaluation-section section-block" id="evaluation">
          <div className="section-wrap">
            <SectionHeading index="07" eyebrow="TRUST / EVALUATION" title="A score is not a benchmark." copy="The scoring weights are prototype heuristics, not statistically calibrated probabilities. We are making the evaluation gaps visible instead of dressing them up as performance claims." />
            <div className="evaluation-layout">
              <Reveal className="evaluation-intro">
                <div className="evaluation-art" aria-hidden="true"><div className="evaluation-art-ring ring-a" /><div className="evaluation-art-ring ring-b" /><div className="evaluation-art-core"><Fingerprint size={32} /></div><span className="evaluation-art-point point-a" /><span className="evaluation-art-point point-b" /><span className="evaluation-art-point point-c" /></div>
                <div className="eyebrow">CURRENT EVIDENCE STATUS</div><h3>Measure the mistakes, not just the hits.</h3><p>A useful scam detector must identify harmful messages while avoiding needless alarm on legitimate banking, delivery, payment, and OTP messages.</p>
                <div className="evaluation-principles"><div><span>01</span><p>Build a labelled, diverse dataset.</p></div><div><span>02</span><p>Separate training, validation, and held-out testing.</p></div><div><span>03</span><p>Report precision, recall, false positives, and limitations.</p></div></div>
              </Reveal>
              <Reveal className="evaluation-table-wrap" delay={0.08}>
                <div className="evaluation-table-heading"><span>Evaluation area</span><span>Current status</span></div>
                {benchmarkRows.map((row) => <div className="evaluation-row" key={row.metric}><div><b>{row.metric}</b><p>{row.copy}</p></div><span className={`eval-state ${row.status === 'Not yet measured' ? 'pending' : 'unpublished'}`}><i />{row.status}</span></div>)}
                <div className="evaluation-footnote"><CircleHelp size={14} /> No public benchmark results are currently published for this project. No accuracy or speed figure is implied here.</div>
              </Reveal>
            </div>
          </div>
        </section>

        <section className="section-wrap section-block specifications-section" id="specifications">
          <SectionHeading index="08" eyebrow="MODEL / SYSTEM NOTES" title="What is running today." copy="Published details are kept separate from local runtime configuration. Unknown or variable values are marked explicitly." />
          <Reveal className="specifications-layout">
            <div className="specifications-title"><div className="spec-badge"><Layers3 size={18} /> SYSTEM PROFILE</div><h3>Local analysis stack</h3><p>ScamShield is an application-level analysis pipeline, not a newly trained foundation model. The Llama component is used through a local Ollama installation.</p><div className="spec-version-line"><span>BUILD STATUS</span><b><i /> Experimental prototype</b></div></div>
            <div className="specification-list">{specRows.map(([label, value], index) => <div className="specification-row" key={label}><span className="specification-index">{String(index + 1).padStart(2, '0')}</span><span className="specification-key">{label}</span><span className="specification-value">{value}</span></div>)}</div>
          </Reveal>
        </section>

        <section className="developer-section section-block" id="developers">
          <div className="section-wrap">
            <SectionHeading index="09" eyebrow="FOR BUILDERS / DEVELOPER EXPERIENCE" title="Keep the interface separate from the inference." copy="The React client talks to a small local FastAPI adapter. That adapter calls the existing ScamShield analyzer; no browser-side API secret is needed for this local setup." />
            <div className="developer-layout">
              <Reveal className="developer-copy">
                <div className="developer-kicker"><Code2 size={16} /> LOCAL API QUICK START</div><h3>Integrate without exposing a key.</h3><p>Start the API from the ScamShield project root so it can import the existing <code>core/</code> modules. Keep Ollama running locally when semantic analysis is needed.</p>
                <div className="quickstart-steps"><div><span>01</span><div><b>Install API requirements</b><code>python -m pip install -r requirements-api.txt</code></div></div><div><span>02</span><div><b>Start the local API</b><code>python -m uvicorn api:app --host 127.0.0.1 --port 8000</code></div></div><div><span>03</span><div><b>Run the frontend</b><code>npm install && npm run dev</code></div></div></div>
                <div className="developer-links"><a className="secondary-button" href="http://127.0.0.1:8000/docs" target="_blank" rel="noreferrer"><BookOpen size={15} /> Local API docs <ExternalLink size={12} /></a><a className="text-link" href="https://github.com/aaravpachouri" target="_blank" rel="noreferrer"><Github size={15} /> GitHub profile <ArrowUpRight size={13} /></a></div>
                <div className="developer-caveat"><AlertIcon /> The API adapter expects your existing <code>core/</code> directory. This uploaded project snapshot does not include those core modules, so the backend will need to be placed beside your working analysis code before inference can succeed.</div>
              </Reveal>
              <Reveal className="developer-code" delay={0.06}><CodeExample onCopy={showToast} /></Reveal>
            </div>
          </div>
        </section>

        <section className="section-wrap section-block roadmap-section" id="roadmap">
          <SectionHeading index="10" eyebrow="OPEN DEVELOPMENT / ROADMAP" title="Make it more reliable, one tested step at a time." copy="The roadmap distinguishes existing prototype code from research and hardening work that remains to be done." />
          <div className="roadmap-list">{roadmap.map((item, index) => <Reveal className={`roadmap-item roadmap-${item.state}`} delay={index * 0.045} key={item.title}><div className="roadmap-marker"><span>{item.state === 'current' ? <Check size={14} /> : String(index + 1).padStart(2, '0')}</span><i /></div><div className="roadmap-copy"><div className="roadmap-label">{item.label}</div><h3>{item.title}</h3><p>{item.copy}</p></div><div className="roadmap-state">{item.state === 'current' ? 'In code' : item.state === 'next' ? 'Next' : 'Planned'}</div></Reveal>)}</div>
        </section>

        <section className="closing-section section-wrap">
          <Reveal className="closing-panel">
            <div className="closing-grid" />
            <div className="closing-orb"><ShieldHalf size={30} /></div>
            <div className="eyebrow">A LITTLE MORE CERTAINTY, A LITTLE LESS PANIC</div>
            <h2>When something feels off,<br /><span>pause and check.</span></h2>
            <p>Use ScamShield as a second opinion. Verify financial or account requests through official channels you find independently.</p>
            <div className="closing-actions"><button className="primary-button" type="button" onClick={() => startPlayground()}><ScanLine size={16} /> Open the playground <ArrowRight size={16} /></button><button className="secondary-button" type="button" onClick={() => scrollTo('developers', reduceMotion)}><Code2 size={16} /> Developer quick start</button></div>
          </Reveal>
        </section>
      </main>

      <footer className="site-footer section-wrap">
        <div className="footer-brand"><span className="brand-symbol small"><ShieldCheck size={18} /></span><span><b>ScamShield</b><small>BEFORE YOU CLICK, CHECK.</small></span></div>
        <p>Experimental analysis aid · A low-risk result never guarantees safety.</p>
        <div className="footer-links"><a href="#overview" onClick={(event) => { event.preventDefault(); scrollTo('overview', reduceMotion); }}>Overview</a><a href="#playground" onClick={(event) => { event.preventDefault(); scrollTo('playground', reduceMotion); }}>Playground</a><a href="#history" onClick={(event) => { event.preventDefault(); scrollTo('history', reduceMotion); }}>History</a><a href="#knowledge" onClick={(event) => { event.preventDefault(); scrollTo('knowledge', reduceMotion); }}>Knowledge</a></div>
      </footer>

      <AnimatePresence>{toast && <motion.div className="toast-message" role="status" initial={{ opacity: 0, y: 12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: 8, scale: 0.98 }}><CheckCircle2 size={16} />{toast}<button type="button" aria-label="Dismiss notification" onClick={() => setToast('')}><X size={14} /></button></motion.div>}</AnimatePresence>
      {apiState === 'offline' && <div className="offline-nudge"><CloudOff size={13} /><span>Local API not reachable</span><button type="button" onClick={() => void refreshHealth()}>Retry</button></div>}
      <div className="hidden-health-description" aria-live="polite">{apiHealth?.service ?? 'ScamShield local API'} {apiHealth?.version ?? ''}</div>
    </div>
  );
}

function AlertIcon() {
  return <span className="alert-icon-wrap"><Eye size={14} /></span>;
}

export default App;

import { useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { BookOpenText, Check, ChevronRight, CircleHelp, Clock3, Gamepad2, Search, ShieldAlert, ShieldCheck, Trash2, Trophy, RotateCcw, ExternalLink } from 'lucide-react';
import type { AnalyzeResponse, SourceMode } from '../types';

export interface SavedAnalysis {
  id: string;
  createdAt: string;
  text: string;
  mode: SourceMode;
  score: number;
  level: string;
  category: string;
  response: AnalyzeResponse;
}

function riskTone(level: string) {
  if (/high/i.test(level)) return 'danger';
  if (/suspicious/i.test(level)) return 'warning';
  return 'safe';
}

export function HistoryPanel({ items, onDelete, onClear, onRecheck }: {
  items: SavedAnalysis[];
  onDelete: (id: string) => void;
  onClear: () => void;
  onRecheck: (item: SavedAnalysis) => void;
}) {
  const [query, setQuery] = useState('');
  const filtered = items.filter(item => `${item.text} ${item.category} ${item.level}`.toLowerCase().includes(query.toLowerCase()));
  return <div className="community-panel history-panel">
    <div className="community-panel-head"><div className="community-panel-icon"><Clock3 size={19}/></div><div className="community-panel-title"><h3>Analysis history</h3><p>{items.length} saved {items.length === 1 ? 'check' : 'checks'} · stored in this browser only</p></div><span className="community-count">{items.length}/50</span></div>
    {items.length > 0 && <div className="community-toolbar"><label className="community-search"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search your checks…" aria-label="Search history"/></label><button className="community-quiet-button" type="button" onClick={onClear}><Trash2 size={14}/> Clear all</button></div>}
    {filtered.length === 0 ? <div className="community-empty"><div className="empty-orbit"><ShieldCheck size={25}/></div><h4>{items.length ? 'No matching checks' : 'Your history starts here'}</h4><p>{items.length ? 'Try another search term.' : 'When you analyze a message, it will appear here so you can review the result or run the check again.'}</p></div> : <div className="history-list">{filtered.map(item => <motion.article layout key={item.id} className="history-row"><span className={`history-risk-dot ${riskTone(item.level)}`}/><div className="history-row-copy"><div className="history-row-top"><b>{item.category || 'Message analysis'}</b><time>{new Date(item.createdAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</time></div><p>{item.text.length > 145 ? `${item.text.slice(0, 145)}…` : item.text}</p><div className="history-row-meta"><span>{item.mode}</span><span className={`history-level ${riskTone(item.level)}`}>{item.level}</span><span>{item.score}/100</span></div></div><div className="history-row-actions"><button type="button" title="Analyze this again" aria-label="Analyze this again" onClick={() => onRecheck(item)}><RotateCcw size={15}/></button><button type="button" title="Delete this check" aria-label="Delete this check" onClick={() => onDelete(item.id)}><Trash2 size={15}/></button></div></motion.article>)}</div>}
    <p className="community-privacy-note"><ShieldCheck size={13}/> This history stays in local browser storage on this device. Avoid saving sensitive personal messages on shared devices.</p>
  </div>;
}

const quiz = [
  { category: 'Banking', message: 'Your account will be suspended in 10 minutes. Reply with your OTP to keep it active.', options: ['Likely scam: urgency + OTP request', 'Safe: banks need OTPs to help you', 'Cannot be suspicious without a link'], answer: 0, explanation: 'Never share an OTP with someone who contacts you. Pause and check your bank app or official number independently.' },
  { category: 'Delivery', message: 'Delivery failed. Pay ₹5 at this unfamiliar link to reschedule your parcel.', options: ['Definitely safe because the fee is small', 'Suspicious: unexpected fee + unfamiliar link', 'Safe if the message has a logo'], answer: 1, explanation: 'Small fees can be used to collect card details. Check tracking through the courier’s official app or website instead.' },
  { category: 'Jobs', message: 'Earn ₹8,000 daily from home. Pay a refundable registration fee today to reserve your role.', options: ['Likely legitimate: high salary', 'Suspicious: upfront fee + unrealistic promise', 'Safe if they reply quickly'], answer: 1, explanation: 'Upfront fees and unrealistic earnings are common job-scam warning signs. Verify the employer independently and do not pay to unlock a job.' },
  { category: 'Payments', message: 'A buyer says they sent money and asks you to scan a QR code to receive it.', options: ['Normal way to receive money', 'Suspicious: scanning may initiate a payment', 'Safe if they show a screenshot'], answer: 1, explanation: 'You generally do not need to scan a QR code or enter a UPI PIN to receive money. Check your own payment app balance, not a screenshot.' },
  { category: 'Impersonation', message: 'A relative messages from a new number asking for emergency money and says not to call.', options: ['Send it immediately', 'Pause, call a known number, and verify', 'Trust it if they know your name'], answer: 1, explanation: 'Use a known number or another trusted channel to verify the person. Scammers may copy names, photos, and personal details.' },
];

export function ScamSchool({ onToast }: { onToast?: (message: string) => void }) {
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<Record<number, number>>({});
  const [showResult, setShowResult] = useState(false);
  const current = quiz[index];
  const chosen = answers[index];
  const score = quiz.reduce((sum, item, i) => sum + (answers[i] === item.answer ? 1 : 0), 0);
  function choose(option: number) { if (chosen !== undefined) return; setAnswers(prev => ({ ...prev, [index]: option })); }
  function next() { if (index === quiz.length - 1) setShowResult(true); else setIndex(i => i + 1); }
  function restart() { setIndex(0); setAnswers({}); setShowResult(false); }
  return <div className="game-layout">
    <div className="game-intro"><div className="game-orb"><Gamepad2 size={29}/><span/></div><div className="eyebrow">SCAM SURVIVAL / QUICK CHALLENGE</div><h3>Can you spot the red flags?</h3><p>Five everyday scenarios. Pick the safest response and learn why it matters.</p><div className="game-stat-row"><div><b>05</b><span>scenarios</span></div><div><b>~2 min</b><span>to play</span></div><div><b>0</b><span>personal data needed</span></div></div></div>
    <div className="quiz-card">
      {!showResult ? <>
        <div className="quiz-progress-head"><span>SCENARIO {String(index + 1).padStart(2, '0')} / {String(quiz.length).padStart(2, '0')}</span><span>{score} correct so far</span></div><div className="quiz-progress"><span style={{ width: `${((index + 1) / quiz.length) * 100}%` }}/></div>
        <div className="quiz-category">{current.category}</div><div className="quiz-message">“{current.message}”</div><p className="quiz-question">What is the safest interpretation?</p>
        <div className="quiz-options">{current.options.map((option, i) => <button type="button" key={option} disabled={chosen !== undefined} onClick={() => choose(i)} className={`quiz-option ${chosen === i ? (i === current.answer ? 'correct' : 'incorrect') : chosen !== undefined && i === current.answer ? 'correct' : ''}`}><span className="quiz-option-letter">{String.fromCharCode(65 + i)}</span><span>{option}</span>{chosen !== undefined && i === current.answer && <Check size={16}/>}</button>)}</div>
        <AnimatePresence>{chosen !== undefined && <motion.div className={`quiz-feedback ${chosen === current.answer ? 'good' : 'learn'}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}><b>{chosen === current.answer ? 'Nice catch.' : 'Here is the safer move.'}</b><p>{current.explanation}</p><button type="button" className="text-link" onClick={next}>{index === quiz.length - 1 ? 'See your results' : 'Next scenario'} <ChevronRight size={15}/></button></motion.div>}</AnimatePresence>
      </> : <div className="quiz-final"><div className="game-orb result-orb"><Trophy size={29}/></div><div className="eyebrow">CHALLENGE COMPLETE</div><h3>{score === quiz.length ? 'Digital Guardian!' : score >= 3 ? 'Scam Spotter in training' : 'Every check makes you safer'}</h3><div className="quiz-final-score">{score}<span> / {quiz.length}</span></div><p>{score === quiz.length ? 'Perfect round. Keep verifying requests independently.' : 'Review the explanations and try again. The goal is to pause, verify, and avoid pressure.'}</p><button className="primary-button" type="button" onClick={restart}><RotateCcw size={15}/> Play again</button></div>}
    </div>
  </div>;
}

const lessons = [
  { category: 'Banking', title: 'Never share an OTP, PIN, or password', summary: 'A caller or message claiming to be from a bank does not need you to disclose an OTP.', steps: ['Stop the conversation if someone asks you to read out an OTP.', 'Open the bank app yourself or call a number from the official website/card.', 'If you already shared details, contact your bank immediately using an independently verified channel.'] },
  { category: 'Links', title: 'Read the actual domain', summary: 'A brand name in a URL is not proof that the URL belongs to that brand.', steps: ['Read the hostname from right to left, focusing on the registered domain.', 'Treat shortened links as opaque until you can verify their destination safely.', 'HTTPS encrypts a connection; it does not prove that a website is legitimate.'] },
  { category: 'Payments', title: 'You do not need a UPI PIN to receive money', summary: 'A request to enter a PIN, scan a QR code, or approve a collect request deserves extra scrutiny.', steps: ['Read the payment screen carefully before approving anything.', 'Check the transaction in your own payment app.', 'Never rely only on a screenshot sent by the other person.'] },
  { category: 'Jobs', title: 'Be cautious with upfront job fees', summary: 'Registration, training, security, or equipment fees can be used to pressure job seekers.', steps: ['Research the company through sources you find independently.', 'Do not pay to unlock a promised job or unusually high daily earnings.', 'Protect identity documents and bank details until the employer is verified.'] },
  { category: 'Impersonation', title: 'Verify urgent requests through another channel', summary: 'Scammers can copy logos, names, profile photos, and writing styles.', steps: ['Pause when a message creates panic or secrecy.', 'Call the person using a number you already know.', 'Confirm payment requests with a second trusted person when appropriate.'] },
  { category: 'Reporting', title: 'If you may have been scammed, act quickly', summary: 'Fast reporting can help limit damage, especially when money or account access is involved.', steps: ['Contact your bank or payment provider using its official channel.', 'In India, report cyber financial fraud promptly through the official 1930 helpline and cybercrime.gov.in.', 'Save relevant messages and transaction references; do not forward private information publicly.'] },
];
const categories = ['All', ...Array.from(new Set(lessons.map(item => item.category)))];

export function KnowledgeLibrary() {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('All');
  const [expanded, setExpanded] = useState<string | null>(lessons[0].title);
  const filtered = useMemo(() => lessons.filter(item => (category === 'All' || item.category === category) && `${item.title} ${item.summary} ${item.steps.join(' ')}`.toLowerCase().includes(query.toLowerCase())), [query, category]);
  return <div className="knowledge-layout"><div className="knowledge-toolbar"><label className="community-search"><Search size={15}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search digital safety topics…" aria-label="Search knowledge base"/></label><div className="knowledge-filters">{categories.map(item => <button key={item} type="button" className={category === item ? 'selected' : ''} onClick={() => setCategory(item)}>{item}</button>)}</div></div><div className="knowledge-list">{filtered.map((item, i) => <article className={`knowledge-item ${expanded === item.title ? 'expanded' : ''}`} key={item.title}><button type="button" className="knowledge-question" aria-expanded={expanded === item.title} onClick={() => setExpanded(expanded === item.title ? null : item.title)}><span className="knowledge-number">{String(i + 1).padStart(2, '0')}</span><span className="knowledge-question-copy"><small>{item.category}</small><b>{item.title}</b><span>{item.summary}</span></span><ChevronRight size={18}/></button><AnimatePresence initial={false}>{expanded === item.title && <motion.div className="knowledge-answer" initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}><ul>{item.steps.map(step => <li key={step}><Check size={14}/><span>{step}</span></li>)}</ul></motion.div>}</AnimatePresence></article>)}{filtered.length === 0 && <div className="community-empty"><BookOpenText size={24}/><h4>No articles found</h4><p>Try another phrase or choose a different topic.</p></div>}</div><div className="knowledge-disclaimer"><CircleHelp size={14}/><p>Guidance is general and may change. Use official channels to verify urgent financial or account requests; ScamShield does not replace professional or official advice.</p><a href="https://cybercrime.gov.in/" target="_blank" rel="noreferrer">India cybercrime portal <ExternalLink size={12}/></a></div></div>;
}

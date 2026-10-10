import { ChangeEvent, FormEvent, useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { AlertCircle, ArrowRight, FileImage, Link2, LoaderCircle, MessageSquareText, RefreshCw, ScanLine, ShieldCheck, Sparkles, Upload, X } from 'lucide-react';
import { analyzeScreenshot, analyzeText } from '../lib/api';
import type { AnalyzeResponse, SourceMode } from '../types';
import ResultPanel from './ResultPanel';

interface Props {
  apiOnline: boolean | null;
  onToast?: (message: string) => void;
  onAnalysis?: (response: AnalyzeResponse) => void;
  seed?: { mode: SourceMode; text: string; trigger: number };
}

const exampleMessage = 'Your SBI account will be blocked today. Verify your KYC immediately and enter your OTP: https://sbi-login-verify.example.com/kyc';
const exampleLink = 'https://sbi-login-verify.example.com/kyc';

export default function Playground({ apiOnline, onToast, onAnalysis, seed }: Props) {
  const [mode, setMode] = useState<SourceMode>('Message');
  const [text, setText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [response, setResponse] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!seed || seed.trigger === 0) return;
    setMode(seed.mode);
    setText(seed.text);
    setFile(null);
    setResponse(null);
    setError('');
    if (fileRef.current) fileRef.current.value = '';
  }, [seed?.trigger]);

  function changeMode(next: SourceMode) {
    setMode(next);
    setError('');
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    const selected = event.target.files?.[0] ?? null;
    setError('');
    if (!selected) { setFile(null); return; }
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(selected.type)) {
      setError('Choose a PNG, JPG, or WEBP screenshot.');
      event.target.value = '';
      setFile(null);
      return;
    }
    if (selected.size > 8 * 1024 * 1024) {
      setError('The screenshot must be 8 MB or smaller.');
      event.target.value = '';
      setFile(null);
      return;
    }
    setFile(selected);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError('');
    setResponse(null);
    if (mode === 'Screenshot') {
      if (!file) { setError('Upload a screenshot before starting the analysis.'); return; }
    } else if (!text.trim()) {
      setError(mode === 'Link' ? 'Paste a URL to inspect.' : 'Paste a message to analyze.');
      return;
    }
    if (text.trim().length > 12000) { setError('The input is longer than the 12,000-character API limit.'); return; }

    setLoading(true);
    try {
      const next = mode === 'Screenshot' && file
        ? await analyzeScreenshot(file)
        : await analyzeText(text.trim(), mode === 'Link' ? 'Link' : 'Message');
      setResponse(next);
      onAnalysis?.(next);
      onToast?.('Analysis returned by the local API');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Analysis failed. Check the local API and try again.');
    } finally {
      setLoading(false);
    }
  }

  function loadExample() {
    if (mode === 'Link') setText(exampleLink);
    else if (mode === 'Message') setText(exampleMessage);
    else setError('For screenshot mode, select a screenshot from your device.');
    setResponse(null);
  }

  function clearInput() {
    setText('');
    setFile(null);
    setResponse(null);
    setError('');
    if (fileRef.current) fileRef.current.value = '';
  }

  const tabs: { mode: SourceMode; label: string; icon: typeof MessageSquareText; note: string }[] = [
    { mode: 'Message', label: 'Message', icon: MessageSquareText, note: 'Paste SMS, WhatsApp, email, or social messages.' },
    { mode: 'Screenshot', label: 'Screenshot', icon: FileImage, note: 'Extract readable text from a screenshot using optional local OCR.' },
    { mode: 'Link', label: 'Link', icon: Link2, note: 'Inspect URL structure and embedded warning signals.' },
  ];

  return (
    <div className="playground-layout">
      <motion.div className="playground-workspace" initial={{ opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true, amount: 0.15 }} transition={{ duration: 0.5 }}>
        <div className="playground-bar">
          <div className="playground-title-lockup"><div className="mini-shield"><ShieldCheck size={17} /></div><div><b>Analysis workspace</b><span>Local-first · experimental</span></div></div>
          <div className={`api-status-pill ${apiOnline ? 'online' : apiOnline === false ? 'offline' : 'checking'}`}><i />{apiOnline ? 'LOCAL API REACHABLE' : apiOnline === false ? 'API OFFLINE' : 'CHECKING API'}</div>
        </div>
        <div className="playground-mode-tabs" role="tablist" aria-label="Input type">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return <button key={tab.mode} type="button" role="tab" aria-selected={mode === tab.mode} className={`playground-mode-tab ${mode === tab.mode ? 'selected' : ''}`} onClick={() => changeMode(tab.mode)}><Icon size={16} /><span>{tab.label}</span>{mode === tab.mode && <motion.span className="mode-indicator" layoutId="mode-indicator" />}</button>;
          })}
        </div>
        <div className="mode-description">{tabs.find((tab) => tab.mode === mode)?.note}</div>
        <form onSubmit={submit}>
          <AnimatePresence mode="wait" initial={false}>
            {mode === 'Screenshot' ? (
              <motion.div key="screenshot" className="upload-zone" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.18 }}>
                <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" onChange={onFileChange} hidden aria-label="Choose screenshot file" />
                <div className="upload-symbol"><ScanLine size={25} /></div>
                <h3>{file ? file.name : 'Drop a suspicious screenshot here'}</h3>
                <p>{file ? `${(file.size / 1024).toFixed(0)} KB · ready for local OCR` : 'PNG, JPG, or WEBP · up to 8 MB'}</p>
                <button className="secondary-button" type="button" onClick={() => fileRef.current?.click()}><Upload size={15} /> {file ? 'Choose another image' : 'Choose screenshot'}</button>
                {file && <button className="file-clear" type="button" onClick={() => { setFile(null); if (fileRef.current) fileRef.current.value = ''; }}><X size={13} /> Remove file</button>}
              </motion.div>
            ) : (
              <motion.div key={mode} className="input-wrap" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.18 }}>
                {mode === 'Message' ? <textarea aria-label="Suspicious message" value={text} onChange={(event) => setText(event.target.value)} maxLength={12000} placeholder={'Paste a suspicious message here…\n\nExample: Your account will be blocked today. Verify immediately.'} /> : <input aria-label="Suspicious URL" value={text} onChange={(event) => setText(event.target.value)} maxLength={12000} placeholder="https://example.com/verify" />}
                <div className="input-bottomline"><span>{mode === 'Message' ? 'Keep the original wording for better context.' : 'The app will normalize the URL before analysis.'}</span><span>{text.length.toLocaleString()} / 12,000</span></div>
              </motion.div>
            )}
          </AnimatePresence>
          {error && <motion.div className="inline-error" role="alert" initial={{ opacity: 0, y: -5 }} animate={{ opacity: 1, y: 0 }}><AlertCircle size={16} /><span>{error}</span></motion.div>}
          <div className="playground-actions">
            <button className="primary-button analyze-button" type="submit" disabled={loading}>
              {loading ? <><LoaderCircle className="spin-icon" size={17} /> Analyzing locally…</> : <><ScanLine size={17} /> Analyze {mode === 'Link' ? 'link' : mode === 'Screenshot' ? 'screenshot' : 'message'} <ArrowRight size={16} /></>}
            </button>
            <button className="text-button" type="button" onClick={loadExample} disabled={loading}>Try example</button>
            <button className="icon-button clear-button" type="button" onClick={clearInput} disabled={loading} title="Clear input" aria-label="Clear input"><RefreshCw size={15} /></button>
          </div>
        </form>
        <div className="workspace-foot"><span><ShieldCheck size={14} /> Runs against your configured local API</span><span>History is saved locally in this browser; clear it anytime.</span></div>
        <AnimatePresence>
          {loading && <motion.div className="analysis-progress" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }}><div className="progress-glow" /><div className="progress-copy"><span className="progress-spinner"><LoaderCircle size={15} /></span><span><b>Analysis in progress</b><small>Waiting for the local analysis response…</small></span></div></motion.div>}
        </AnimatePresence>
      </motion.div>
      <div className="playground-side-rail">
        <div className="side-rail-orbit"><div className="side-rail-inner"><ShieldCheck size={24} /></div></div>
        <div className="side-rail-title">Evidence before certainty.</div>
        <p>ScamShield combines explicit rule signals, URL structure checks, and local model assessment where available.</p>
        <div className="side-rail-list">
          <div><span className="rail-icon blue"><ShieldCheck size={15} /></span><span><b>Transparent signals</b><small>See the indicators behind the result.</small></span></div>
          <div><span className="rail-icon violet"><Sparkles size={15} /></span><span><b>Local AI assessment</b><small>Uses Ollama when configured and reachable.</small></span></div>
          <div><span className="rail-icon cyan"><Link2 size={15} /></span><span><b>URL structure</b><small>Heuristics, not reputation guarantees.</small></span></div>
        </div>
        {apiOnline === false && <div className="side-rail-alert"><AlertCircle size={14} /> Start the API at <code>127.0.0.1:8000</code> to run an analysis.</div>}
      </div>
      {response && <div className="result-span"><ResultPanel response={response} onCopy={onToast} /></div>}
    </div>
  );
}

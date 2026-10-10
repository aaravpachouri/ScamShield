import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowLeft, ArrowRight, BadgeCheck, BookOpen, Check, CheckCircle2, CircleHelp,
  Clock3, Flame, GraduationCap, RotateCcw, ShieldAlert, ShieldCheck, Shuffle,
  Sparkles, Target, Trophy, X
} from "lucide-react";
import { scamSchoolScenarios, scenarioCategories, type ScamScenario, type Verdict } from "../data/scamSchoolScenarios";
import "./ScamSchool.css";

type Props = { onToast?: (message: string) => void };
type AnswerRecord = { selected: Verdict; correct: boolean };

const verdictInfo: Record<Verdict, { label: string; short: string; icon: typeof ShieldAlert }> = {
  scam: { label: "Likely scam", short: "SCAM", icon: ShieldAlert },
  legitimate: { label: "Likely legitimate", short: "LEGITIMATE", icon: ShieldCheck },
  verify: { label: "Needs verification", short: "VERIFY", icon: CircleHelp }
};

const options: { value: Verdict; title: string; description: string }[] = [
  { value: "scam", title: "Likely a scam", description: "There are meaningful warning signs." },
  { value: "legitimate", title: "Likely legitimate", description: "The message fits a normal, expected action." },
  { value: "verify", title: "Need more context", description: "Verify independently before deciding." }
];

function shuffle<T>(items: T[]): T[] {
  const result = [...items];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function chooseRound(pool: ScamScenario[], count: number) {
  const balanced = (["scam", "legitimate", "verify"] as Verdict[]).flatMap(verdict =>
    shuffle(pool.filter(item => item.verdict === verdict))
  );
  return shuffle(balanced).slice(0, Math.min(count, pool.length));
}

export default function ScamSchool({ onToast }: Props) {
  const [category, setCategory] = useState("All");
  const [difficulty, setDifficulty] = useState("All");
  const [roundSize, setRoundSize] = useState(10);
  const [round, setRound] = useState<ScamScenario[]>(() => chooseRound(scamSchoolScenarios, 10));
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<Record<string, AnswerRecord>>({});
  const [showSummary, setShowSummary] = useState(false);

  const pool = useMemo(() => scamSchoolScenarios.filter(item =>
    (category === "All" || item.category === category) &&
    (difficulty === "All" || item.difficulty === difficulty)
  ), [category, difficulty]);

  const current = round[index];
  const answer = current ? answers[current.id] : undefined;
  const correctCount = round.filter(item => answers[item.id]?.correct).length;
  const answeredCount = round.filter(item => answers[item.id]).length;
  const verdict = current ? verdictInfo[current.verdict] : verdictInfo.verify;
  const VerdictIcon = verdict.icon;

  function startRound(nextSize = roundSize, nextPool = pool) {
    if (!nextPool.length) {
      onToast?.("No scenarios match those filters.");
      return;
    }
    setRound(chooseRound(nextPool, nextSize));
    setIndex(0);
    setAnswers({});
    setShowSummary(false);
  }

  function selectAnswer(value: Verdict) {
    if (!current || answer) return;
    const correct = value === current.verdict;
    setAnswers(previous => ({ ...previous, [current.id]: { selected: value, correct } }));
  }

  function goNext() {
    if (index < round.length - 1) setIndex(value => value + 1);
    else setShowSummary(true);
  }

  function goPrevious() {
    if (index > 0) setIndex(value => value - 1);
  }

  function restartMissed() {
    const missed = round.filter(item => answers[item.id] && !answers[item.id].correct);
    if (!missed.length) {
      startRound();
      return;
    }
    setRound(shuffle(missed));
    setIndex(0);
    setAnswers({});
    setShowSummary(false);
  }

  function changeFilters(nextCategory: string, nextDifficulty: string, nextSize = roundSize) {
    setCategory(nextCategory);
    setDifficulty(nextDifficulty);
    setRoundSize(nextSize);
    const nextPool = scamSchoolScenarios.filter(item =>
      (nextCategory === "All" || item.category === nextCategory) &&
      (nextDifficulty === "All" || item.difficulty === nextDifficulty)
    );
    startRound(nextSize, nextPool);
  }

  if (!pool.length) {
    return <div className="ss-school"><div className="ss-empty"><CircleHelp size={28}/><h3>No scenarios found</h3><p>Choose another category or difficulty.</p><button onClick={() => changeFilters("All", "All")}>Reset filters</button></div></div>;
  }

  return (
    <div className="ss-school">
      <section className="ss-school-hero">
        <div className="ss-hero-copy">
          <div className="ss-eyebrow"><span className="ss-live-dot" /> DIGITAL SAFETY TRAINING</div>
          <h3>Train your instincts.<br/><span>Not your anxiety.</span></h3>
          <p>Learn to spot scams, recognise normal messages, and know when the safest answer is to verify.</p>
          <div className="ss-hero-metrics">
            <div><b>{scamSchoolScenarios.length}</b><span>scenarios</span></div>
            <div><b>03</b><span>decision types</span></div>
            <div><b>∞</b><span>ways to practise</span></div>
          </div>
        </div>
        <div className="ss-hero-art" aria-hidden="true">
          <div className="ss-art-ring ring-one"/><div className="ss-art-ring ring-two"/>
          <div className="ss-art-core"><ShieldCheck size={42}/><span>SCAMSHIELD</span><small>LEARN / VERIFY / PROTECT</small></div>
          <i className="ss-art-node node-one"/><i className="ss-art-node node-two"/><i className="ss-art-node node-three"/>
          <div className="ss-art-chip chip-one"><Target size={14}/> Think critically</div>
          <div className="ss-art-chip chip-two"><BadgeCheck size={14}/> Verify independently</div>
        </div>
      </section>

      <section className="ss-training-bar">
        <div className="ss-training-label"><GraduationCap size={17}/><span><b>Practice mode</b><small>New mix each round · no repeats within a round</small></span></div>
        <div className="ss-training-controls">
          <label>Category<select value={category} onChange={e => changeFilters(e.target.value, difficulty)}>{scenarioCategories.map(item => <option key={item}>{item}</option>)}</select></label>
          <label>Difficulty<select value={difficulty} onChange={e => changeFilters(category, e.target.value)}>{["All", "Starter", "Intermediate", "Expert"].map(item => <option key={item}>{item}</option>)}</select></label>
          <label>Round<select value={roundSize} onChange={e => changeFilters(category, difficulty, Number(e.target.value))}>{[5, 10, 15, 25].map(item => <option key={item} value={item}>{item} questions</option>)}</select></label>
          <button className="ss-icon-button" title="Shuffle a new round" onClick={() => startRound()}><Shuffle size={16}/></button>
        </div>
      </section>

      <div className="ss-game-grid">
        <main className="ss-quiz-card">
          {!showSummary && current ? (
            <>
              <div className="ss-quiz-topline"><span>SCENARIO <b>{String(index + 1).padStart(2, "0")}</b><i>/</i>{String(round.length).padStart(2, "0")}</span><span><Clock3 size={13}/> About {Math.max(1, Math.ceil((round.length - index) * 0.35))} min left</span></div>
              <div className="ss-progress-track"><span style={{width: `${((index + 1) / round.length) * 100}%`}}/></div>
              <div className="ss-scenario-meta"><span className="ss-category-tag">{current.category}</span><span className={`ss-difficulty ${current.difficulty.toLowerCase()}`}>{current.difficulty}</span><span className="ss-scenario-id">{current.id}</span></div>
              <AnimatePresence mode="wait">
                <motion.div key={current.id} className="ss-scenario-content" initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} exit={{opacity:0,y:-8}} transition={{duration:.22}}>
                  <div className="ss-message-window">
                    <div className="ss-message-window-top"><span className="ss-message-avatar"><BookOpen size={16}/></span><span><b>Message received</b><small>SIMULATED EXAMPLE · NOT A REAL MESSAGE</small></span><span className="ss-message-dots">•••</span></div>
                    <div className="ss-message-body">{current.message}</div>
                    <div className="ss-message-context"><CircleHelp size={15}/><p><b>Context</b>{current.context}</p></div>
                  </div>
                  <div className="ss-question-heading"><span>YOUR CALL</span><h4>What is the safest interpretation?</h4><p>Judge the evidence—not just a keyword, logo, or the fact that money is mentioned.</p></div>
                  <div className="ss-answer-options">
                    {options.map((option, i) => {
                      const selected = answer?.selected === option.value;
                      const revealCorrect = !!answer && current.verdict === option.value;
                      return <button key={option.value} disabled={!!answer} onClick={() => selectAnswer(option.value)} className={`ss-answer-option ${selected ? "selected" : ""} ${answer && revealCorrect ? "correct" : ""} ${selected && !answer?.correct ? "wrong" : ""}`}>
                        <span className="ss-option-letter">{String.fromCharCode(65+i)}</span><span className="ss-option-copy"><b>{option.title}</b><small>{option.description}</small></span>{answer && revealCorrect ? <CheckCircle2 size={18}/> : selected && !answer?.correct ? <X size={18}/> : <ArrowRight size={16} className="ss-option-arrow"/>}
                      </button>;
                    })}
                  </div>
                  <AnimatePresence>
                    {answer && <motion.div className={`ss-feedback ${answer.correct ? "is-correct" : "is-learning"}`} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}}>
                      <div className="ss-feedback-head"><span className="ss-feedback-icon">{answer.correct ? <Check size={16}/> : <Sparkles size={16}/>}</span><div><b>{answer.correct ? "Good judgement." : "A useful lesson."}</b><span>Expected interpretation: <strong>{verdict.label}</strong></span></div></div>
                      <p>{current.explanation}</p>
                      <div className="ss-signal-row"><span>KEY SIGNAL</span><b>{current.signal}</b></div>
                      <div className="ss-next-step"><ShieldCheck size={16}/><p><b>Safer next step</b>{current.nextStep}</p></div>
                    </motion.div>}
                  </AnimatePresence>
                </motion.div>
              </AnimatePresence>
              <div className="ss-quiz-footer"><button className="ss-back-button" onClick={goPrevious} disabled={index === 0}><ArrowLeft size={15}/> Previous</button><span>{answeredCount}/{round.length} answered</span><button className="ss-next-button" onClick={goNext} disabled={!answer}>{index === round.length - 1 ? "View results" : "Next scenario"}<ArrowRight size={15}/></button></div>
            </>
          ) : (
            <motion.div className="ss-summary" initial={{opacity:0,y:10}} animate={{opacity:1,y:0}}>
              <div className="ss-summary-icon"><Trophy size={29}/></div><div className="ss-eyebrow">ROUND COMPLETE</div>
              <h3>{correctCount === round.length ? "Excellent judgement." : correctCount >= round.length * .7 ? "You're building good instincts." : "Every round is practice."}</h3>
              <div className="ss-score">{correctCount}<span> / {round.length}</span></div>
              <p>You correctly interpreted {correctCount} of {round.length} scenarios. The goal is to notice evidence, verify context, and avoid rushed decisions.</p>
              <div className="ss-summary-stats"><div><b>{round.filter(s=>s.verdict==="scam").length}</b><span>scam cases</span></div><div><b>{round.filter(s=>s.verdict==="legitimate").length}</b><span>legitimate cases</span></div><div><b>{round.filter(s=>s.verdict==="verify").length}</b><span>verify cases</span></div></div>
              <div className="ss-summary-actions"><button className="ss-next-button" onClick={() => startRound()}><Shuffle size={15}/> New round</button><button className="ss-secondary-button" onClick={restartMissed}><RotateCcw size={15}/> Review mistakes</button></div>
              <div className="ss-summary-note"><CircleHelp size={14}/> These are educational simulations, not guarantees about how a real message should be classified.</div>
            </motion.div>
          )}
        </main>
        <aside className="ss-side-panel">
          <div className="ss-side-heading"><span className="ss-side-icon"><Target size={17}/></span><div><b>Round intelligence</b><small>YOUR CURRENT SESSION</small></div></div>
          <div className="ss-side-score"><span>Correct answers</span><b>{correctCount}<small>/{round.length}</small></b><div className="ss-side-progress"><span style={{width:`${round.length ? correctCount / round.length * 100 : 0}%`}}/></div></div>
          <div className="ss-side-stat"><span><CheckCircle2 size={15}/> Answered</span><b>{answeredCount} / {round.length}</b></div>
          <div className="ss-side-stat"><span><Flame size={15}/> Accuracy</span><b>{answeredCount ? Math.round(correctCount / answeredCount * 100) : 0}%</b></div>
          <div className="ss-side-divider"/>
          <div className="ss-side-heading"><span className="ss-side-icon"><Sparkles size={17}/></span><div><b>Learning principles</b><small>REMEMBER THESE</small></div></div>
          <ul className="ss-principles"><li>Urgency is a warning sign, not proof by itself.</li><li>A logo or sender name does not authenticate a message.</li><li>Verify through a channel you find independently.</li><li>Never disclose an OTP, password, or UPI PIN to a caller.</li></ul>
          <div className="ss-side-bottom"><ShieldCheck size={15}/><span>Pause. Check. Then act.</span></div>
        </aside>
      </div>
      <div className="ss-bank-footer"><span><BookOpen size={14}/> {scamSchoolScenarios.length} curated scenario variants</span><span><Shuffle size={14}/> Randomised rounds</span><span><ShieldCheck size={14}/> Scam · Legitimate · Verify</span></div>
    </div>
  );
}

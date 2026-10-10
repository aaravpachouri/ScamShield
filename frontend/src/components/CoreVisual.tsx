import { motion, useReducedMotion } from 'framer-motion';
import { Activity, ShieldCheck, Sparkles } from 'lucide-react';

const nodes = [
  { x: 76, y: 104, r: 4 }, { x: 127, y: 64, r: 3 }, { x: 194, y: 80, r: 4 },
  { x: 252, y: 58, r: 3 }, { x: 310, y: 100, r: 4 }, { x: 345, y: 164, r: 3 },
  { x: 319, y: 235, r: 4 }, { x: 263, y: 291, r: 3 }, { x: 194, y: 307, r: 4 },
  { x: 122, y: 280, r: 3 }, { x: 70, y: 224, r: 4 }, { x: 52, y: 164, r: 3 },
  { x: 119, y: 151, r: 3 }, { x: 158, y: 120, r: 4 }, { x: 230, y: 126, r: 3 },
  { x: 271, y: 165, r: 4 }, { x: 245, y: 221, r: 3 }, { x: 183, y: 244, r: 4 },
  { x: 133, y: 211, r: 3 }, { x: 163, y: 175, r: 4 }, { x: 213, y: 177, r: 3 },
];

const links = [
  [0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 8], [8, 9], [9, 10], [10, 11], [11, 0],
  [0, 12], [12, 13], [13, 14], [14, 4], [12, 18], [18, 17], [17, 16], [16, 6], [13, 19], [19, 20], [20, 15], [15, 5],
  [19, 17], [13, 18], [14, 20], [20, 16], [14, 15], [18, 19], [15, 16], [2, 13], [9, 17], [10, 18], [7, 16],
];

export default function CoreVisual() {
  const reduceMotion = useReducedMotion();
  return (
    <div className="core-visual-wrap" aria-label="Animated abstract visualization of ScamShield's analysis pipeline">
      <div className="core-ambient core-ambient-a" />
      <div className="core-ambient core-ambient-b" />
      <div className="core-orbit orbit-one" />
      <div className="core-orbit orbit-two" />
      <div className="core-orbit orbit-three" />
      <motion.div
        className="core-orbit-dot orbit-dot-one"
        animate={reduceMotion ? undefined : { rotate: 360 }}
        transition={{ duration: 17, repeat: Infinity, ease: 'linear' }}
      ><i /></motion.div>
      <motion.div
        className="core-orbit-dot orbit-dot-two"
        animate={reduceMotion ? undefined : { rotate: -360 }}
        transition={{ duration: 24, repeat: Infinity, ease: 'linear' }}
      ><i /></motion.div>
      <svg className="core-network" viewBox="0 0 400 365" role="presentation">
        <defs>
          <linearGradient id="networkStroke" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#45b9ff" stopOpacity=".15" />
            <stop offset="48%" stopColor="#59caff" stopOpacity=".72" />
            <stop offset="100%" stopColor="#a084ff" stopOpacity=".25" />
          </linearGradient>
          <radialGradient id="coreLight">
            <stop offset="0%" stopColor="#83dcff" stopOpacity=".34" />
            <stop offset="60%" stopColor="#328eff" stopOpacity=".1" />
            <stop offset="100%" stopColor="#328eff" stopOpacity="0" />
          </radialGradient>
        </defs>
        <circle cx="200" cy="183" r="127" fill="url(#coreLight)" />
        {links.map(([a, b], idx) => (
          <motion.line
            key={`${a}-${b}`}
            x1={nodes[a].x} y1={nodes[a].y} x2={nodes[b].x} y2={nodes[b].y}
            stroke="url(#networkStroke)" strokeWidth={idx % 3 === 0 ? 1.15 : 0.7}
            strokeDasharray={idx % 4 === 0 ? '3 7' : 'none'}
            initial={{ opacity: 0.18 }}
            animate={reduceMotion ? undefined : { opacity: [0.18, 0.72, 0.25] }}
            transition={{ duration: 3.2 + (idx % 5) * 0.4, repeat: Infinity, delay: idx * 0.035, ease: 'easeInOut' }}
          />
        ))}
        {nodes.map((node, idx) => (
          <g key={`${node.x}-${node.y}`}>
            <motion.circle
              cx={node.x} cy={node.y} r={node.r + 5}
              fill="#38b6ff" opacity=".08"
              animate={reduceMotion ? undefined : { opacity: [0.04, 0.22, 0.04], r: [node.r + 3, node.r + 9, node.r + 3] }}
              transition={{ duration: 2.2 + (idx % 4) * 0.6, repeat: Infinity, delay: idx * 0.08 }}
            />
            <circle cx={node.x} cy={node.y} r={node.r} fill={idx % 4 === 0 ? '#b7a1ff' : '#7de1ff'} />
          </g>
        ))}
      </svg>
      <motion.div
        className="core-center"
        animate={reduceMotion ? undefined : { y: [0, -5, 0], scale: [1, 1.015, 1] }}
        transition={{ duration: 5.2, repeat: Infinity, ease: 'easeInOut' }}
      >
        <div className="core-center-halo" />
        <div className="core-center-icon"><ShieldCheck size={47} strokeWidth={1.45} /></div>
        <div className="core-center-label">SCAMSHIELD</div>
        <div className="core-center-sub">SIGNAL ANALYSIS</div>
      </motion.div>
      <motion.div className="visual-label visual-label-top" animate={reduceMotion ? undefined : { y: [0, -4, 0] }} transition={{ duration: 5, repeat: Infinity }}>
        <span className="visual-label-icon"><Activity size={14} /></span>
        <span><b>Signal engine</b><small>Rule-based evidence</small></span>
      </motion.div>
      <motion.div className="visual-label visual-label-right" animate={reduceMotion ? undefined : { y: [0, 4, 0] }} transition={{ duration: 5.5, repeat: Infinity }}>
        <span className="visual-label-icon violet"><Sparkles size={14} /></span>
        <span><b>Local intelligence</b><small>Llama 3.2 · Ollama</small></span>
      </motion.div>
      <div className="visual-coordinate coord-one">N 28° 36' / E 77° 12'</div>
      <div className="visual-coordinate coord-two">PIPELINE / 01</div>
    </div>
  );
}

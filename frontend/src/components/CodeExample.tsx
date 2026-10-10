import { useState } from 'react';
import { Check, Copy, Terminal } from 'lucide-react';

type Language = 'Python' | 'cURL' | 'JavaScript';

const examples: Record<Language, string> = {
  Python: `import requests\n\nresponse = requests.post(\n    "http://127.0.0.1:8000/api/analyze",\n    json={\n        "text": "Your account will be blocked. Verify now.",\n        "source_mode": "Message",\n    },\n    timeout=120,\n)\nresponse.raise_for_status()\nresult = response.json()["result"]\nprint(result["final_level"], result["final_score"])`,
  cURL: `curl -X POST http://127.0.0.1:8000/api/analyze \\\n  -H "Content-Type: application/json" \\\n  -d '{"text":"Your account will be blocked. Verify now.","source_mode":"Message"}'`,
  JavaScript: `const response = await fetch("http://127.0.0.1:8000/api/analyze", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({\n    text: "Your account will be blocked. Verify now.",\n    source_mode: "Message",\n  }),\n});\nif (!response.ok) throw new Error(` + '`${response.status} ${response.statusText}`' + `);\nconst data = await response.json();\nconsole.log(data.result.final_level, data.result.final_score);`,
};

interface Props {
  onCopy?: (message: string) => void;
}

export default function CodeExample({ onCopy }: Props) {
  const [language, setLanguage] = useState<Language>('Python');
  const [copied, setCopied] = useState(false);

  async function copyCode() {
    try {
      await navigator.clipboard.writeText(examples[language]);
      setCopied(true);
      onCopy?.('Code copied to clipboard');
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      onCopy?.('Clipboard access was blocked by this browser. Select the code and copy it manually.');
    }
  }

  return (
    <div className="code-panel">
      <div className="code-toolbar">
        <div className="code-file-label"><span className="terminal-dot" /><Terminal size={14} /> Local API · POST /api/analyze</div>
        <div className="code-toolbar-actions">
          <div className="code-tabs" role="tablist" aria-label="Code language">
            {(['Python', 'cURL', 'JavaScript'] as Language[]).map((item) => (
              <button type="button" role="tab" aria-selected={language === item} className={language === item ? 'active' : ''} key={item} onClick={() => setLanguage(item)}>{item}</button>
            ))}
          </div>
          <button className="icon-button code-copy" type="button" onClick={copyCode} aria-label="Copy code">{copied ? <Check size={15} /> : <Copy size={15} />}</button>
        </div>
      </div>
      <pre className="code-content"><code>{examples[language]}</code></pre>
      <div className="code-footnote"><span className="live-dot" /> Example uses the local API adapter. It requires the API and analysis modules to be running on your machine.</div>
    </div>
  );
}

import React, { useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  Activity,
  AlertTriangle,
  Bot,
  Braces,
  CheckCircle2,
  Download,
  FileText,
  Gauge,
  Globe2,
  Layers,
  Play,
  Radar,
  ShieldAlert,
  ShieldCheck,
  Sparkles
} from 'lucide-react';
import './styles.css';

const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8080';

const starterArchitecture = {
  name: 'Cloud-Native E-Commerce Platform',
  description: 'React storefront with REST API, PostgreSQL, Redis, S3 receipts, payment webhooks, CI/CD, admin portal, and observability.',
  components: [
    { id: 'frontend', name: 'React Frontend', type: 'external', trustBoundary: 'Internet' },
    { id: 'api', name: 'REST API', type: 'process', trustBoundary: 'Application VPC' },
    { id: 'db', name: 'PostgreSQL DB', type: 'datastore', trustBoundary: 'Data Tier' },
    { id: 'redis', name: 'Redis Cache', type: 'cache', trustBoundary: 'Data Tier' },
    { id: 's3', name: 'S3 Receipt Bucket', type: 'storage', trustBoundary: 'Cloud Storage' },
    { id: 'payment', name: 'Payment Gateway', type: 'external', trustBoundary: 'Third Party' },
    { id: 'admin', name: 'Admin Backoffice', type: 'process', trustBoundary: 'Operations' },
    { id: 'cicd', name: 'CI/CD Pipeline', type: 'process', trustBoundary: 'Build System' }
  ],
  flows: [
    { from: 'React Frontend', to: 'REST API', protocol: 'HTTPS', data: 'login, cart, checkout requests' },
    { from: 'REST API', to: 'PostgreSQL DB', protocol: 'TLS', data: 'orders and customer emails' },
    { from: 'REST API', to: 'Redis Cache', protocol: 'TLS', data: 'cart/session cache' },
    { from: 'REST API', to: 'S3 Receipt Bucket', protocol: 'HTTPS', data: 'receipt objects' },
    { from: 'Payment Gateway', to: 'REST API', protocol: 'HTTPS', data: 'payment webhooks' },
    { from: 'CI/CD Pipeline', to: 'REST API', protocol: 'HTTPS', data: 'container deployments' }
  ]
};

function severityClass(severity) {
  return `severity ${String(severity).toLowerCase()}`;
}

function riskLabel(score) {
  if (score >= 80) return 'Critical';
  if (score >= 55) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

function MetricCard({ icon, label, value, accent }) {
  return (
    <article className={`metric-card ${accent || ''}`}>
      <div className="metric-icon">{icon}</div>
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  );
}

function RiskRing({ score, label }) {
  const safeScore = Math.max(0, Math.min(100, score || 0));
  return (
    <div className="risk-ring" style={{ '--score': `${safeScore * 3.6}deg` }}>
      <div>
        <strong>{safeScore}</strong>
        <span>{label || riskLabel(safeScore)}</span>
      </div>
    </div>
  );
}

function JsonEditor({ value, onChange }) {
  return (
    <textarea
      spellCheck="false"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      aria-label="Architecture JSON editor"
    />
  );
}

function App() {
  const [mode, setMode] = useState('architecture');
  const [editorText, setEditorText] = useState(JSON.stringify(starterArchitecture, null, 2));
  const [analysis, setAnalysis] = useState(null);
  const [websiteUrl, setWebsiteUrl] = useState('https://example.com');
  const [websiteScan, setWebsiteScan] = useState(null);
  const [status, setStatus] = useState('');
  const [entered, setEntered] = useState(false);

  const architecture = useMemo(() => {
    try {
      return JSON.parse(editorText);
    } catch {
      return null;
    }
  }, [editorText]);

  const topThreats = useMemo(() => analysis?.threats?.slice(0, 8) || [], [analysis]);
  const failedWebsiteFindings = useMemo(() => websiteScan?.findings?.filter((item) => !item.passed) || [], [websiteScan]);

  const heatmap = useMemo(() => {
    if (!analysis) return [];
    const grouped = new Map();
    for (const threat of analysis.threats) {
      const current = grouped.get(threat.component) || { component: threat.component, max: 0, count: 0 };
      current.max = Math.max(current.max, threat.dread);
      current.count += 1;
      grouped.set(threat.component, current);
    }
    return [...grouped.values()].sort((a, b) => b.max - a.max).slice(0, 10);
  }, [analysis]);

  function loadSample() {
    setEditorText(JSON.stringify(starterArchitecture, null, 2));
    setAnalysis(null);
    setStatus('Sample architecture loaded.');
  }

  async function analyzeArchitecture() {
    try {
      if (!architecture) {
        setStatus('Invalid JSON. Fix the architecture input first.');
        return;
      }
      setStatus('Analyzing architecture with STRIDE, DREAD, and OWASP mapping...');
      const response = await fetch(`${apiUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(architecture)
      });
      const payload = await response.json();
      if (!response.ok) {
        setStatus(payload.error || 'Architecture analysis failed.');
        return;
      }
      setAnalysis(payload);
      setStatus(`Architecture analysis complete. Generated ${payload.summary.total} threats.`);
    } catch (error) {
      setStatus(`Cannot connect to backend API at ${apiUrl}. Start the backend first.`);
      console.error(error);
    }
  }

  async function scanWebsite() {
    try {
      setStatus('Running passive website security scan...');
      const response = await fetch(`${apiUrl}/scan-website`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: websiteUrl })
      });
      const payload = await response.json();
      if (!response.ok) {
        setStatus(payload.error || 'Website scan failed.');
        return;
      }
      setWebsiteScan(payload);
      setStatus(`Website scan complete. ${payload.summary.failed} issue(s) found from passive checks.`);
    } catch (error) {
      setStatus(`Cannot connect to backend API at ${apiUrl}. Start the backend first.`);
      console.error(error);
    }
  }

  async function downloadArchitectureReport() {
    try {
      if (!architecture) {
        setStatus('Invalid JSON. Fix the architecture input first.');
        return;
      }
      const response = await fetch(`${apiUrl}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(architecture)
      });
      if (!response.ok) {
        setStatus('Report generation failed.');
        return;
      }
      downloadText(await response.text(), 'stride-architecture-threat-report.md');
      setStatus('Architecture report downloaded.');
    } catch (error) {
      setStatus(`Cannot connect to backend API at ${apiUrl}. Start the backend first.`);
      console.error(error);
    }
  }

  function downloadWebsiteReport() {
    if (!websiteScan) {
      setStatus('Run a website scan before downloading its report.');
      return;
    }
    const rows = websiteScan.findings
      .map((item) => `| ${item.check} | ${item.passed ? "Pass" : item.severity} | ${item.dread} | ${item.owasp} | ${item.mitigation} |`)
      .join('\n');
    const report = `# Website Risk Report

## Target

- Input URL: ${websiteScan.target}
- Final URL: ${websiteScan.finalUrl}
- HTTP status: ${websiteScan.status}
- Risk score: ${websiteScan.summary.riskScore}/100
- Passive only: Yes

## Page Signals

- Title: ${websiteScan.pageSignals.title}
- Forms: ${websiteScan.pageSignals.forms}
- Password inputs: ${websiteScan.pageSignals.passwordInputs}
- Inline scripts: ${websiteScan.pageSignals.inlineScripts}
- HTTP references: ${websiteScan.pageSignals.httpLinks}

## Findings

| Check | Result | DREAD | OWASP | Mitigation |
| --- | --- | ---: | --- | --- |
${rows}

## Recommendations

${websiteScan.recommendations.map((item) => `- ${item}`).join('\n')}
`;
    downloadText(report, 'website-risk-report.md');
    setStatus('Website report downloaded.');
  }

  function downloadText(text, filename) {
    const blob = new Blob([text], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }

  if (!entered) {
    return <EntryPage onEnter={() => setEntered(true)} />;
  }

  return (
    <main>
      <header className="hero">
        <nav className="topbar">
          <div className="brand">
            <ShieldCheck size={25} />
            <span>STRIDE Risk Intelligence</span>
          </div>
          <div className="mode-switch" aria-label="Analysis mode">
            <button type="button" className={mode === 'architecture' ? 'active' : ''} onClick={() => setMode('architecture')}>
              <Braces size={16} />
              Architecture
            </button>
            <button type="button" className={mode === 'website' ? 'active' : ''} onClick={() => setMode('website')}>
              <Globe2 size={16} />
              Website
            </button>
          </div>
        </nav>

        <section className="hero-grid">
          <div>
            <p className="eyebrow">AI-powered passive security analysis</p>
            <h1>Threat modeling for designs and live websites</h1>
            <p className="hero-copy">
              Analyze architecture diagrams with STRIDE or scan a public URL for security headers,
              transport weaknesses, cookie signals, and OWASP-mapped risks.
            </p>
          </div>
          <div className="hero-visual" aria-hidden="true">
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <Radar size={90} />
            <span>STRIDE</span>
          </div>
        </section>
      </header>

      <section className="overview">
        <MetricCard icon={<ShieldAlert size={22} />} label="Architecture threats" value={analysis?.summary.total || 0} accent="red" />
        <MetricCard icon={<Gauge size={22} />} label="Website risk" value={websiteScan ? `${websiteScan.summary.riskScore}/100` : '0/100'} accent="blue" />
        <MetricCard icon={<Layers size={22} />} label="Components" value={architecture?.components?.length ?? '-'} />
        <MetricCard icon={<Activity size={22} />} label="Passive checks" value={websiteScan?.summary.totalChecks || 13} />
      </section>

      {status && <section className="status-banner">{status}</section>}

      {mode === 'architecture' ? (
        <section className="workspace">
          <aside className="input-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Design-time mode</p>
                <h2>Architecture Analyzer</h2>
              </div>
              <FileText size={22} />
            </div>
            <JsonEditor value={editorText} onChange={setEditorText} />
            <div className="actions">
              <button type="button" onClick={loadSample}>
                <Sparkles size={17} />
                Sample
              </button>
              <button type="button" className="primary" onClick={analyzeArchitecture}>
                <Play size={17} />
                Analyze
              </button>
              <button type="button" className="secondary" onClick={downloadArchitectureReport}>
                <Download size={17} />
                Report
              </button>
            </div>
          </aside>

          <section className="analysis-panel">
            <div className="ai-strip">
              <Bot size={24} />
              <div>
                <strong>Architecture threat engine</strong>
                <p>Component keyword detection, STRIDE rule expansion, DREAD scoring, OWASP mapping, and mitigation ranking.</p>
              </div>
            </div>

            <div className="split">
              <section className="panel">
                <h2>Component Risk Heatmap</h2>
                <div className="heatmap">
                  {heatmap.length === 0 && <p className="empty">Run analysis to populate component risk.</p>}
                  {heatmap.map((item) => (
                    <div className="heat-row" key={item.component}>
                      <span>{item.component}</span>
                      <div className="bar"><i style={{ width: `${Math.min(100, item.max * 10)}%` }} /></div>
                      <strong>{item.max.toFixed(1)}</strong>
                    </div>
                  ))}
                </div>
              </section>

              <section className="panel">
                <h2>STRIDE Distribution</h2>
                <div className="stride-list">
                  {analysis ? Object.entries(analysis.summary.byStride).map(([key, value]) => (
                    <div key={key}><span>{key}</span><strong>{value}</strong></div>
                  )) : <p className="empty">No distribution yet.</p>}
                </div>
              </section>
            </div>

            <ThreatTable threats={topThreats} emptyText="Run architecture analysis to generate threats." />
          </section>
        </section>
      ) : (
        <section className="website-workspace">
          <section className="scanner-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">Runtime mode</p>
                <h2>Website Risk Scanner</h2>
              </div>
              <Globe2 size={24} />
            </div>
            <div className="url-box">
              <input value={websiteUrl} onChange={(event) => setWebsiteUrl(event.target.value)} placeholder="https://example.com" />
              <button type="button" className="primary" onClick={scanWebsite}>
                <Radar size={17} />
                Scan URL
              </button>
              <button type="button" className="secondary" onClick={downloadWebsiteReport}>
                <Download size={17} />
                Report
              </button>
            </div>
            <p className="hint">This performs passive public checks only: no login, brute force, crawling, exploitation, or attack traffic.</p>
          </section>

          <section className="website-results">
            <div className="score-panel">
              <RiskRing score={websiteScan?.summary.riskScore || 0} />
              <div>
                <p className="eyebrow">Website posture</p>
                <h2>{websiteScan?.pageSignals.title || 'No scan yet'}</h2>
                <p>{websiteScan ? websiteScan.finalUrl : 'Enter a website URL and scan to calculate passive DREAD risk.'}</p>
              </div>
            </div>

            <div className="website-grid">
              <MetricCard icon={<CheckCircle2 size={22} />} label="Passed checks" value={websiteScan?.summary.passed || 0} />
              <MetricCard icon={<AlertTriangle size={22} />} label="Failed checks" value={websiteScan?.summary.failed || 0} accent="red" />
              <MetricCard icon={<Gauge size={22} />} label="Avg DREAD" value={websiteScan?.summary.averageDread || 0} accent="blue" />
              <MetricCard icon={<Braces size={22} />} label="Inline scripts" value={websiteScan?.pageSignals.inlineScripts ?? '-'} />
            </div>

            <section className="panel">
              <h2>Security Checks</h2>
              <div className="check-grid">
                {websiteScan ? websiteScan.findings.map((item) => (
                  <article className={`check-card ${item.passed ? 'pass' : 'fail'}`} key={item.id}>
                    <div>
                      {item.passed ? <CheckCircle2 size={18} /> : <AlertTriangle size={18} />}
                      <strong>{item.check}</strong>
                    </div>
                    <span>{item.passed ? 'Pass' : item.severity}</span>
                    <p>{item.passed ? item.evidence : item.threat}</p>
                  </article>
                )) : <p className="empty">Scan a URL to see passive security checks.</p>}
              </div>
            </section>

            <ThreatTable threats={failedWebsiteFindings} emptyText="No website risks yet. Run a scan to populate findings." />
          </section>
        </section>
      )}
    </main>
  );
}

function EntryPage({ onEnter }) {
  return (
    <section className="entry-fullscreen-container">
      <div className="data-flow-waves" aria-hidden="true" />
      <div className="glow-ambient-one" aria-hidden="true" />
      <div className="glow-ambient-two" aria-hidden="true" />
      <div className="radar-blip" aria-hidden="true" />

      <nav className="entry-nav">
        <div className="brand">
          <ShieldCheck size={28} />
          <span className="brand-text-glow">STRIDE Risk Intelligence</span>
        </div>
        <span className="entry-pill">AI-powered security analysis</span>
      </nav>

      <div className="entry-content">
        <section className="entry-copy">
          <div className="badge-wrapper">
            <span className="eyebrow-accent-line" />
            <p className="eyebrow">Threat modeling & website risk scanner</p>
          </div>
          <h1>
            Find security <span className="text-gradient">risks</span> <br />
            before attackers do
          </h1>
          <p className="hero-description">
            Automate architectural risk evaluation using STRIDE modeling matrices, compute granular DREAD severity matrices, and instantly check running deployments against live passive OWASP exposure profiles.
          </p>
          <div className="entry-actions">
            <button type="button" className="entry-button-premium" onClick={onEnter}>
              <Radar size={22} />
              <span>Enter Platform Matrix</span>
            </button>
          </div>
        </section>

        <section className="entry-console-premium" aria-label="Platform preview">
          <div className="console-top">
            <div className="console-dots">
              <span />
              <span />
              <span />
            </div>
            <div className="console-title">engine_status: active</div>
          </div>
          <div className="console-lines-premium">
            <p><span className="line-num">01</span> <strong>node:</strong> architecture + website</p>
            <p><span className="line-num">02</span> <strong>engine:</strong> STRIDE / DREAD / OWASP</p>
            <p><span className="line-num">03</span> <strong>checks:</strong> CSP, HSTS, HTTPS, cookies</p>
            <p><span className="line-num">04</span> <strong>output:</strong> dashboard + report</p>
          </div>
          <div className="console-radar-container">
            <div className="radar-scanner-ring">
              <Radar size={96} />
            </div>
          </div>
        </section>
      </div>

      <div className="entry-cards-premium">
        <article className="cyber-card-interactive">
          <Braces size={24} className="card-icon" />
          <div>
            <strong>Architecture Analysis</strong>
            <span>Generate STRIDE threats from components and data flows.</span>
          </div>
        </article>

        <article className="cyber-card-interactive">
          <Globe2 size={24} className="card-icon" />
          <div>
            <strong>Website URL Scan</strong>
            <span>Check passive public security headers and page signals.</span>
          </div>
        </article>

        <article className="cyber-card-interactive">
          <Gauge size={24} className="card-icon" />
          <div>
            <strong>Risk Intelligence</strong>
            <span>Calculate DREAD score, severity, OWASP class, and fixes.</span>
          </div>
        </article>
      </div>
    </section>
  );
}

function ThreatTable({ threats, emptyText }) {
  return (
    <section className="panel">
      <h2>Risk Register</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Component / Check</th>
              <th>Threat</th>
              <th>STRIDE</th>
              <th>DREAD</th>
              <th>Severity</th>
              <th>OWASP</th>
            </tr>
          </thead>
          <tbody>
            {threats.map((threat) => (
              <tr key={`${threat.id}-${threat.component || threat.check}`}>
                <td>{threat.component || threat.check}</td>
                <td>{threat.threat}</td>
                <td>{threat.stride}</td>
                <td>{threat.dread}</td>
                <td><span className={severityClass(threat.severity)}>{threat.severity}</span></td>
                <td>{threat.owasp}</td>
              </tr>
            ))}
            {threats.length === 0 && (
              <tr>
                <td colSpan="6" className="empty">{emptyText}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

createRoot(document.getElementById('root')).render(<App />);
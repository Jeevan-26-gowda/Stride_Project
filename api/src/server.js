import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { z } from 'zod';

const port = Number(process.env.PORT || 8080);

const componentStride = {
  external: ['Spoofing', 'Repudiation', 'Information Disclosure'],
  process: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'],
  datastore: ['Tampering', 'Information Disclosure', 'Denial of Service'],
  storage: ['Tampering', 'Information Disclosure', 'Repudiation'],
  cache: ['Tampering', 'Information Disclosure', 'Denial of Service'],
  queue: ['Tampering', 'Repudiation', 'Denial of Service'],
  identity: ['Spoofing', 'Elevation of Privilege', 'Repudiation'],
  network: ['Spoofing', 'Information Disclosure', 'Denial of Service']
};

const catalog = [
  ['api gateway service', 'Tampering', 'Injection modifies application data or backend queries', 'A05 Injection', 'Parameterized queries, strict schemas, server-side validation, and query allowlists', [10, 8, 8, 9, 9]],
  ['api gateway service', 'Spoofing', 'Missing or weak authentication allows impersonation', 'A07 Authentication Failures', 'OIDC, short-lived tokens, MFA, and deny-by-default middleware', [9, 8, 7, 9, 8]],
  ['api gateway service', 'Elevation of Privilege', 'User changes role or tenant identifiers to access privileged functions', 'A01 Broken Access Control', 'Central authorization policies and route-level authorization tests', [9, 8, 8, 9, 8]],
  ['api gateway service', 'Denial of Service', 'Large payloads or repeated requests exhaust API workers', 'A02 Security Misconfiguration', 'Body limits, rate limits, circuit breakers, quotas, and backpressure', [7, 9, 8, 8, 8]],
  ['api gateway service', 'Repudiation', 'User denies a sensitive action because audit events are incomplete', 'A09 Security Logging and Alerting Failures', 'Correlation IDs, structured audit logs, signed events, and retention rules', [6, 7, 6, 7, 6]],
  ['api gateway service', 'Information Disclosure', 'Verbose errors reveal stack traces, secrets, or internal hosts', 'A10 Server-Side Request Forgery and Error Handling Risks', 'Central exception mapping, generic errors, redaction, and secure logging', [7, 8, 6, 7, 6]],
  ['frontend web react client', 'Tampering', 'Cross-site scripting changes client behavior or steals tokens', 'A05 Injection', 'Output encoding, CSP, dependency scanning, and safe rendering patterns', [9, 7, 7, 8, 8]],
  ['frontend web react client', 'Information Disclosure', 'Sensitive tokens are stored in browser storage and read by injected scripts', 'A04 Cryptographic Failures', 'HttpOnly cookies, minimal browser storage, token rotation, and CSP', [8, 7, 7, 8, 7]],
  ['frontend web react client', 'Spoofing', 'Stolen session token is reused to impersonate a user', 'A07 Authentication Failures', 'Secure cookies, short token lifetime, refresh rotation, and anomaly detection', [9, 8, 8, 8, 8]],
  ['postgres mysql database db sql', 'Tampering', 'SQL injection or overbroad service account modifies records', 'A05 Injection', 'Parameterized queries, least-privilege DB roles, and integrity checks', [10, 8, 8, 9, 9]],
  ['postgres mysql database db sql', 'Information Disclosure', 'Customer or business data is exposed through overbroad queries or backups', 'A01 Broken Access Control; A04 Cryptographic Failures', 'Row-level authorization, encrypted backups, restore controls, and data minimization', [9, 8, 8, 9, 9]],
  ['postgres mysql database db sql', 'Denial of Service', 'Slow queries or connection exhaustion make persistence unavailable', 'A06 Vulnerable and Outdated Components', 'Connection pooling, query timeouts, indexes, and load testing', [7, 8, 6, 8, 7]],
  ['redis cache', 'Tampering', 'Cache poisoning changes session, cart, or authorization state', 'A08 Software and Data Integrity Failures', 'Private networking, signed cache values, TTLs, and strict key namespaces', [8, 7, 7, 8, 7]],
  ['redis cache', 'Information Disclosure', 'Exposed cache leaks session or temporary business data', 'A02 Security Misconfiguration', 'Private subnet, Redis AUTH/TLS, network policies, and no public endpoint', [8, 7, 7, 8, 8]],
  ['redis cache', 'Denial of Service', 'Unbounded keys or credential-stuffing traffic consumes cache memory', 'A02 Security Misconfiguration', 'Rate limits, maxmemory policy, quotas, key expiry, and abuse detection', [7, 9, 8, 8, 8]],
  ['s3 bucket blob storage', 'Information Disclosure', 'Public object storage exposes files or receipts', 'A02 Security Misconfiguration', 'Block public access, bucket policies, access analyzer, and private endpoints', [9, 8, 7, 8, 8]],
  ['s3 bucket blob storage', 'Tampering', 'Attacker overwrites uploaded objects or injects malicious content', 'A08 Software and Data Integrity Failures', 'Object versioning, content validation, KMS, and least-privilege write roles', [7, 6, 6, 7, 6]],
  ['s3 bucket blob storage', 'Repudiation', 'Objects are deleted or changed without a traceable audit trail', 'A09 Security Logging and Alerting Failures', 'Object lock, versioning, data event logging, and lifecycle approvals', [6, 6, 5, 7, 5]],
  ['payment stripe gateway', 'Spoofing', 'Forged webhook marks unpaid orders as paid', 'A07 Authentication Failures', 'Webhook signatures, timestamp windows, nonce replay cache, and idempotency keys', [10, 8, 8, 8, 8]],
  ['payment stripe gateway', 'Tampering', 'Payment amount changes between checkout and authorization', 'A08 Software and Data Integrity Failures', 'Server-side totals, signed payment intents, provider response comparison, and idempotency', [10, 7, 7, 8, 7]],
  ['payment stripe gateway', 'Repudiation', 'Payment disputes cannot be investigated because signed events are not retained', 'A09 Security Logging and Alerting Failures', 'Persist signed callbacks, correlation IDs, SIEM alerts, and reconciliation jobs', [7, 7, 6, 7, 6]],
  ['admin operator backoffice', 'Spoofing', 'Phished admin credentials are used for product or refund changes', 'A07 Authentication Failures', 'MFA, privileged access management, device posture checks, and session risk scoring', [9, 7, 7, 9, 7]],
  ['admin operator backoffice', 'Elevation of Privilege', 'Support user accesses owner-only administration functions', 'A01 Broken Access Control', 'RBAC/ABAC, separation of duties, admin policy tests, and approval workflow', [8, 7, 7, 8, 7]],
  ['cdn waf edge', 'Denial of Service', 'Bot traffic overwhelms the edge or origin', 'A02 Security Misconfiguration', 'WAF rules, bot detection, rate limits, CDN caching, and origin shielding', [7, 9, 8, 8, 8]],
  ['cdn waf edge', 'Information Disclosure', 'Cache key mistake serves one user response to another', 'A02 Security Misconfiguration', 'Avoid caching authenticated responses, cache-control headers, and cache variance tests', [9, 6, 6, 8, 6]],
  ['ci cd pipeline github', 'Tampering', 'Compromised dependency or image is deployed to production', 'A03 Software Supply Chain Failures', 'SBOM, lockfiles, image signing, protected branches, and dependency scanning', [10, 7, 7, 9, 8]],
  ['ci cd pipeline github', 'Information Disclosure', 'Build logs or container layers expose cloud credentials', 'A04 Cryptographic Failures', 'Secret manager, masked logs, layer scanning, short-lived credentials, and rotation', [9, 6, 7, 8, 7]],
  ['iam identity auth', 'Spoofing', 'Weak identity configuration enables account takeover', 'A07 Authentication Failures', 'Strong MFA, conditional access, breached-password checks, and session controls', [9, 8, 7, 9, 8]],
  ['iam identity auth', 'Elevation of Privilege', 'Overpermissive role allows access outside intended scope', 'A01 Broken Access Control', 'Least privilege, permission boundaries, policy simulation, and access reviews', [9, 6, 6, 8, 7]],
  ['log observability monitoring', 'Information Disclosure', 'Logs contain tokens, emails, or sensitive transaction metadata', 'A09 Security Logging and Alerting Failures', 'Log redaction, data classification, least-privilege log access, and retention limits', [8, 6, 6, 7, 6]],
  ['log observability monitoring', 'Repudiation', 'Privileged changes lack immutable audit evidence', 'A09 Security Logging and Alerting Failures', 'Tamper-resistant audit storage, admin event schemas, and privileged-change alerts', [7, 7, 6, 8, 6]],
  ['queue kafka rabbit sqs', 'Tampering', 'Message body is modified before processing', 'A08 Software and Data Integrity Failures', 'Message signatures, schema validation, producer identity, and dead-letter inspection', [8, 7, 7, 8, 7]],
  ['queue kafka rabbit sqs', 'Denial of Service', 'Message flood blocks consumers and delays critical work', 'A06 Vulnerable and Outdated Components', 'Consumer autoscaling, quotas, backpressure, and poison-message handling', [7, 8, 7, 8, 7]],
  ['network vpc ingress load balancer', 'Spoofing', 'Untrusted service reaches internal endpoints through weak network boundaries', 'A02 Security Misconfiguration', 'Network policies, mTLS, security groups, and private service discovery', [8, 7, 7, 8, 7]],
  ['container docker kubernetes k8s', 'Elevation of Privilege', 'Container breakout or exposed runtime socket compromises the host', 'A02 Security Misconfiguration', 'Rootless containers, no socket mounts, seccomp/AppArmor, and admission policies', [10, 5, 6, 9, 6]],
  ['config secret env', 'Information Disclosure', 'Default or leaked credentials are reused in production', 'A02 Security Misconfiguration', 'Secret scanning, environment separation, secret rotation, and deployment policy checks', [9, 7, 8, 8, 8]]
].map((item, index) => ({
  id: `TH-${String(index + 1).padStart(3, '0')}`,
  match: item[0].split(' '),
  stride: item[1],
  threat: item[2],
  owasp: item[3],
  mitigation: item[4],
  base: item[5]
}));

const inputSchema = z.object({
  name: z.string().min(1).max(120).default('Cloud-Native Application'),
  description: z.string().max(2000).optional().default(''),
  components: z.array(z.object({
    id: z.string().min(1).max(60),
    name: z.string().min(1).max(80),
    type: z.enum(Object.keys(componentStride)).default('process'),
    trustBoundary: z.string().max(80).optional().default('Application')
  })).min(2).max(40),
  flows: z.array(z.object({
    from: z.string().min(1),
    to: z.string().min(1),
    protocol: z.string().max(40).optional().default('HTTPS'),
    data: z.string().max(120).optional().default('Application data')
  })).min(1).max(80)
});

const websiteScanSchema = z.object({
  url: z.string().min(4).max(300)
});

const sampleArchitecture = {
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

function score(base, component, description) {
  const boost = /cloud|kubernetes|public|internet|payment|customer|pii|s3|bucket/i.test(`${component.name} ${description}`) ? 0.4 : 0;
  const scores = base.map((value) => Math.min(10, Number((value + boost).toFixed(1))));
  return { scores, dread: Number((scores.reduce((sum, value) => sum + value, 0) / 5).toFixed(1)) };
}

function severity(dread) {
  if (dread >= 8) return 'Critical';
  if (dread >= 7) return 'High';
  if (dread >= 5) return 'Medium';
  return 'Low';
}

function generic(stride) {
  const map = {
    Spoofing: ['Unverified identity allows an attacker to pretend to be this component', 'A07 Authentication Failures', 'Strong authentication, mutual TLS, signed tokens, and service identity checks', [8, 7, 7, 8, 7]],
    Tampering: ['Input or state can be modified without integrity checks', 'A08 Software and Data Integrity Failures', 'Integrity validation, signed messages, strict schemas, and least-privilege write paths', [7, 7, 6, 7, 6]],
    Repudiation: ['Security-relevant actions cannot be traced to a durable audit event', 'A09 Security Logging and Alerting Failures', 'Structured audit logs, correlation IDs, immutable retention, and alert coverage', [6, 6, 6, 7, 6]],
    'Information Disclosure': ['Sensitive data may be exposed through weak access control or encryption gaps', 'A04 Cryptographic Failures', 'Encryption, data minimization, authorization checks, and secure error handling', [8, 6, 6, 8, 6]],
    'Denial of Service': ['Resource exhaustion can make this component unavailable', 'A02 Security Misconfiguration', 'Rate limits, quotas, autoscaling, timeouts, and capacity monitoring', [7, 8, 7, 8, 7]],
    'Elevation of Privilege': ['Weak authorization allows access beyond the intended privilege level', 'A01 Broken Access Control', 'Central authorization, least privilege, policy tests, and privileged workflow reviews', [9, 7, 7, 8, 7]]
  };
  const [threat, owasp, mitigation, base] = map[stride];
  return { threat, owasp, mitigation, base };
}

function analyze(input) {
  const architecture = inputSchema.parse(input);
  const threats = [];

  for (const component of architecture.components) {
    const allowed = componentStride[component.type] || componentStride.process;
    const haystack = `${component.name} ${component.id} ${component.type}`.toLowerCase();
    const used = new Set();
    for (const item of catalog) {
      if (!allowed.includes(item.stride) || !item.match.some((term) => haystack.includes(term))) continue;
      const dread = score(item.base, component, architecture.description);
      used.add(item.stride);
      threats.push({
        id: item.id,
        component: component.name,
        componentType: component.type,
        trustBoundary: component.trustBoundary,
        stride: item.stride,
        threat: item.threat,
        damage: dread.scores[0],
        reproducibility: dread.scores[1],
        exploitability: dread.scores[2],
        affectedUsers: dread.scores[3],
        discoverability: dread.scores[4],
        dread: dread.dread,
        severity: severity(dread.dread),
        owasp: item.owasp,
        mitigation: item.mitigation,
        source: 'Knowledge base'
      });
    }
    for (const stride of allowed) {
      if (used.has(stride)) continue;
      const item = generic(stride);
      const dread = score(item.base, component, architecture.description);
      threats.push({
        id: `GEN-${component.id}-${stride.replaceAll(' ', '-')}`,
        component: component.name,
        componentType: component.type,
        trustBoundary: component.trustBoundary,
        stride,
        threat: item.threat,
        damage: dread.scores[0],
        reproducibility: dread.scores[1],
        exploitability: dread.scores[2],
        affectedUsers: dread.scores[3],
        discoverability: dread.scores[4],
        dread: dread.dread,
        severity: severity(dread.dread),
        owasp: item.owasp,
        mitigation: item.mitigation,
        source: 'STRIDE rule'
      });
    }
  }

  for (const [index, flow] of architecture.flows.entries()) {
    const base = /http$|ftp|plain|tcp/i.test(flow.protocol) ? [8, 8, 7, 8, 8] : [7, 6, 6, 7, 6];
    const dread = score(base, { name: `${flow.from} to ${flow.to}` }, architecture.description);
    threats.push({
      id: `FLOW-${String(index + 1).padStart(2, '0')}`,
      component: `${flow.from} -> ${flow.to}`,
      componentType: 'flow',
      trustBoundary: 'Data Flow',
      stride: /http$|ftp|plain|tcp/i.test(flow.protocol) ? 'Information Disclosure' : 'Tampering',
      threat: `${flow.protocol} flow carrying ${flow.data} can be intercepted, replayed, or modified`,
      damage: dread.scores[0],
      reproducibility: dread.scores[1],
      exploitability: dread.scores[2],
      affectedUsers: dread.scores[3],
      discoverability: dread.scores[4],
      dread: dread.dread,
      severity: severity(dread.dread),
      owasp: 'A02 Security Misconfiguration; A08 Software and Data Integrity Failures',
      mitigation: 'Use TLS, request signing where needed, replay protection, schema validation, and network policy',
      source: 'Flow rule'
    });
  }

  threats.sort((a, b) => b.dread - a.dread || a.component.localeCompare(b.component));
  const summary = threats.reduce((acc, item) => {
    acc.total += 1;
    acc.bySeverity[item.severity] = (acc.bySeverity[item.severity] || 0) + 1;
    acc.byStride[item.stride] = (acc.byStride[item.stride] || 0) + 1;
    return acc;
  }, { total: 0, bySeverity: {}, byStride: {} });

  return {
    architecture,
    summary,
    threats,
    recommendations: [
      'Prioritize Critical and High DREAD findings before deployment.',
      'Place identity, API, database, cache, and object storage inside explicit trust boundaries.',
      'Add CI checks for dependency scanning, secret scanning, IaC policy, and container image signing.',
      'Use audit logs and correlation IDs for every privileged or financial workflow.'
    ]
  };
}

function report(analysis) {
  const rows = analysis.threats.map((item) => `| ${item.component} | ${item.stride} | ${item.threat} | ${item.dread} | ${item.severity} | ${item.owasp} | ${item.mitigation} |`).join('\n');
  return `# ${analysis.architecture.name} Threat Model

## Executive Summary

Automated STRIDE analysis found ${analysis.summary.total} threats across ${analysis.architecture.components.length} components and ${analysis.architecture.flows.length} data flows.

## Severity Summary

${Object.entries(analysis.summary.bySeverity).map(([key, value]) => `- ${key}: ${value}`).join('\n')}

## Threat Register

| Component | STRIDE | Threat | DREAD | Severity | OWASP | Mitigation |
| --- | --- | --- | ---: | --- | --- | --- |
${rows}

## Recommendations

${analysis.recommendations.map((item) => `- ${item}`).join('\n')}
`;
}

function websiteFinding(id, check, passed, threat, stride, owasp, mitigation, base, evidence) {
  const dread = score(base, { name: check }, threat);
  return {
    id,
    check,
    passed,
    threat,
    stride,
    owasp,
    mitigation,
    evidence,
    damage: dread.scores[0],
    reproducibility: dread.scores[1],
    exploitability: dread.scores[2],
    affectedUsers: dread.scores[3],
    discoverability: dread.scores[4],
    dread: passed ? 0 : dread.dread,
    severity: passed ? 'Pass' : severity(dread.dread)
  };
}

function normalizeWebsiteUrl(rawUrl) {
  const value = rawUrl.trim();
  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const parsed = new URL(withProtocol);
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP and HTTPS websites can be scanned.');
  }
  return parsed;
}

async function scanWebsite(input) {
  const parsedInput = websiteScanSchema.parse(input);
  const targetUrl = normalizeWebsiteUrl(parsedInput.url);
  const startedAt = new Date().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  let response;
  let html = '';
  try {
    response = await fetch(targetUrl, {
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'STRIDE-Project-Passive-Security-Analyzer/1.0'
      }
    });
    html = await response.text();
  } finally {
    clearTimeout(timeout);
  }

  const finalUrl = new URL(response.url);
  const headers = response.headers;
  const header = (name) => headers.get(name);
  const setCookie = headers.get('set-cookie') || '';
  const htmlLower = html.slice(0, 250000).toLowerCase();
  const forms = (htmlLower.match(/<form\b/g) || []).length;
  const passwordInputs = (htmlLower.match(/type=["']password["']/g) || []).length;
  const httpLinks = (htmlLower.match(/http:\/\//g) || []).length;
  const inlineScripts = (htmlLower.match(/<script(?![^>]+src=)/g) || []).length;
  const serverHeader = header('server');
  const poweredBy = header('x-powered-by');

  const findings = [
    websiteFinding(
      'WEB-001',
      'HTTPS Enabled',
      finalUrl.protocol === 'https:',
      'Website is served over plain HTTP, allowing traffic interception or modification',
      'Information Disclosure',
      'A02 Security Misconfiguration; A04 Cryptographic Failures',
      'Force HTTPS, redirect HTTP to HTTPS, and use modern TLS configuration',
      [9, 8, 7, 9, 8],
      finalUrl.protocol
    ),
    websiteFinding(
      'WEB-002',
      'Strict-Transport-Security',
      Boolean(header('strict-transport-security')),
      'Missing HSTS allows downgrade or SSL stripping attacks',
      'Tampering',
      'A02 Security Misconfiguration',
      'Add Strict-Transport-Security with max-age, includeSubDomains, and preload after validation',
      [8, 7, 7, 8, 7],
      header('strict-transport-security') || 'Header missing'
    ),
    websiteFinding(
      'WEB-003',
      'Content-Security-Policy',
      Boolean(header('content-security-policy')),
      'Missing CSP increases impact of cross-site scripting and injection attacks',
      'Tampering',
      'A05 Injection',
      'Add a restrictive Content-Security-Policy for scripts, styles, frames, images, and connections',
      [9, 7, 7, 8, 8],
      header('content-security-policy') || 'Header missing'
    ),
    websiteFinding(
      'WEB-004',
      'Clickjacking Protection',
      Boolean(header('x-frame-options')) || /frame-ancestors/i.test(header('content-security-policy') || ''),
      'Missing frame protection allows clickjacking through hostile embedded pages',
      'Spoofing',
      'A01 Broken Access Control',
      'Use CSP frame-ancestors and/or X-Frame-Options DENY or SAMEORIGIN',
      [7, 7, 6, 8, 7],
      header('x-frame-options') || 'No X-Frame-Options or CSP frame-ancestors found'
    ),
    websiteFinding(
      'WEB-005',
      'MIME Sniffing Protection',
      /nosniff/i.test(header('x-content-type-options') || ''),
      'Missing nosniff can let browsers interpret content as an unsafe MIME type',
      'Tampering',
      'A05 Injection; A02 Security Misconfiguration',
      'Set X-Content-Type-Options: nosniff',
      [6, 6, 6, 7, 6],
      header('x-content-type-options') || 'Header missing'
    ),
    websiteFinding(
      'WEB-006',
      'Referrer Policy',
      Boolean(header('referrer-policy')),
      'Missing referrer policy may leak sensitive URL paths or query data to third-party sites',
      'Information Disclosure',
      'A04 Cryptographic Failures',
      'Set Referrer-Policy to strict-origin-when-cross-origin or stricter',
      [6, 7, 5, 7, 6],
      header('referrer-policy') || 'Header missing'
    ),
    websiteFinding(
      'WEB-007',
      'Permissions Policy',
      Boolean(header('permissions-policy')),
      'Missing browser permissions policy leaves sensitive APIs available to embedded or third-party content',
      'Elevation of Privilege',
      'A05 Security Misconfiguration',
      'Add Permissions-Policy to restrict camera, microphone, geolocation, payment, and sensors',
      [6, 6, 5, 7, 6],
      header('permissions-policy') || 'Header missing'
    ),
    websiteFinding(
      'WEB-008',
      'Server Technology Disclosure',
      !serverHeader && !poweredBy,
      'Server or framework headers reveal technology details useful for targeted attacks',
      'Information Disclosure',
      'A02 Security Misconfiguration',
      'Remove or minimize Server and X-Powered-By headers at the edge or application server',
      [5, 8, 5, 6, 8],
      [serverHeader && `Server: ${serverHeader}`, poweredBy && `X-Powered-By: ${poweredBy}`].filter(Boolean).join('; ') || 'No obvious disclosure header'
    ),
    websiteFinding(
      'WEB-009',
      'Secure Cookies',
      !setCookie || /secure/i.test(setCookie),
      'Cookies without Secure flag may be sent over insecure channels',
      'Information Disclosure',
      'A07 Authentication Failures; A04 Cryptographic Failures',
      'Set Secure, HttpOnly, and SameSite on session and authentication cookies',
      [8, 7, 7, 8, 7],
      setCookie ? 'Set-Cookie observed' : 'No Set-Cookie header observed'
    ),
    websiteFinding(
      'WEB-010',
      'HttpOnly Cookies',
      !setCookie || /httponly/i.test(setCookie),
      'Cookies without HttpOnly are easier to steal through injected JavaScript',
      'Information Disclosure',
      'A05 Injection; A07 Authentication Failures',
      'Set HttpOnly on session cookies and avoid storing tokens in browser-accessible storage',
      [8, 7, 7, 8, 7],
      setCookie ? 'Set-Cookie observed' : 'No Set-Cookie header observed'
    ),
    websiteFinding(
      'WEB-011',
      'Password Form Transport',
      !(passwordInputs > 0 && finalUrl.protocol !== 'https:'),
      'Password fields are present on a non-HTTPS page',
      'Information Disclosure',
      'A07 Authentication Failures; A04 Cryptographic Failures',
      'Serve login and sensitive forms only over HTTPS',
      [10, 9, 8, 9, 9],
      `${passwordInputs} password input(s) detected`
    ),
    websiteFinding(
      'WEB-012',
      'Mixed Content Signals',
      httpLinks === 0,
      'HTTP resource references can create mixed-content or downgrade exposure',
      'Tampering',
      'A02 Security Misconfiguration',
      'Use HTTPS URLs for images, scripts, forms, APIs, and static assets',
      [7, 7, 6, 7, 7],
      `${httpLinks} http:// reference(s) detected`
    ),
    websiteFinding(
      'WEB-013',
      'Inline Script Exposure',
      inlineScripts <= 3 || Boolean(header('content-security-policy')),
      'Multiple inline scripts without CSP increase XSS blast radius',
      'Tampering',
      'A05 Injection',
      'Move scripts to trusted files, use nonces/hashes, and enforce CSP',
      [8, 7, 7, 8, 8],
      `${inlineScripts} inline script block(s) detected`
    )
  ];

  const failed = findings.filter((item) => !item.passed);
  const averageDread = failed.length
    ? Number((failed.reduce((sum, item) => sum + item.dread, 0) / failed.length).toFixed(1))
    : 0;
  const riskScore = Math.min(100, Math.round(failed.reduce((sum, item) => sum + item.dread, 0) * 6));
  const summary = failed.reduce((acc, item) => {
    acc.bySeverity[item.severity] = (acc.bySeverity[item.severity] || 0) + 1;
    acc.byStride[item.stride] = (acc.byStride[item.stride] || 0) + 1;
    return acc;
  }, { totalChecks: findings.length, passed: findings.length - failed.length, failed: failed.length, averageDread, riskScore, bySeverity: {}, byStride: {} });

  return {
    target: targetUrl.toString(),
    finalUrl: finalUrl.toString(),
    status: response.status,
    scannedAt: startedAt,
    passiveOnly: true,
    pageSignals: {
      forms,
      passwordInputs,
      inlineScripts,
      httpLinks,
      title: html.match(/<title[^>]*>(.*?)<\/title>/is)?.[1]?.trim()?.slice(0, 120) || 'Untitled page'
    },
    summary,
    findings,
    recommendations: [
      'Fix missing security headers before public release.',
      'Use CSP and HSTS as high-impact baseline controls.',
      'Avoid exposing server/framework details in response headers.',
      'Use Secure, HttpOnly, and SameSite flags for sensitive cookies.',
      'Treat this as a passive public-signal scan, not a full penetration test.'
    ]
  };
}

const app = express();
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173' }));
app.use(express.json({ limit: '128kb' }));

app.get('/health', (_req, res) => res.json({ ok: true, engine: 'stride-dread-owasp', aiMode: 'heuristic-nlp' }));
app.get('/sample-architecture', (_req, res) => res.json(sampleArchitecture));
app.get('/threat-catalog', (_req, res) => res.json(catalog.map(({ base, ...item }) => item)));
app.post('/scan-website', async (req, res) => {
  try {
    res.json(await scanWebsite(req.body));
  } catch (error) {
    const message = error.message === 'fetch failed'
      ? 'Website could not be reached. Check the URL, internet connection, or target availability.'
      : error.message;
    res.status(400).json({ error: message });
  }
});
app.post('/analyze', (req, res) => {
  try {
    res.json(analyze(req.body));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/report', (req, res) => {
  try {
    res.type('text/markdown').send(report(analyze(req.body)));
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(port, () => console.log(`threat-modeling-api listening on ${port}`));

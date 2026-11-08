// Single source of truth for CYBERLENS vocabulary on the frontend.
// These keys MUST match the backend contract (docs/api-contract.md).

export const CLASSIFICATIONS = {
  low_risk: {
    key: 'low_risk',
    label: 'Low Risk',
    tone: 'green',
    headline: 'No known threat detected',
    description:
      'No threat intelligence match and no significant risk indicators were found in the checks that completed. This is not a guarantee that the target is safe.',
  },
  suspicious: {
    key: 'suspicious',
    label: 'Suspicious',
    tone: 'amber',
    headline: 'Caution advised',
    description:
      'Heuristic indicators warrant caution. No confirmed threat intelligence match was returned.',
  },
  high_risk: {
    key: 'high_risk',
    label: 'High Risk',
    tone: 'orange',
    headline: 'Strong risk indicators',
    description:
      'Multiple strong phishing or fraud indicators were found. Avoid interacting with this target.',
  },
  confirmed_malicious: {
    key: 'confirmed_malicious',
    label: 'Confirmed Malicious',
    tone: 'red',
    headline: 'Threat intelligence match',
    description:
      'At least one threat intelligence provider returned a confirmed match for this target. Do not interact with it.',
  },
  inconclusive: {
    key: 'inconclusive',
    label: 'Inconclusive',
    tone: 'gray',
    headline: 'Insufficient evidence',
    description:
      'Not enough checks completed to make a meaningful assessment. An inconclusive result is not a clean result.',
  },
};

export const CLASSIFICATION_ORDER = [
  'low_risk',
  'suspicious',
  'high_risk',
  'confirmed_malicious',
  'inconclusive',
];

// Provider / check statuses (brief §7).
export const CHECK_STATUS = {
  completed: { label: 'Completed', tone: 'blue' },
  no_match: { label: 'No match found', tone: 'green' },
  match_found: { label: 'Match found', tone: 'red' },
  unavailable: { label: 'Unavailable', tone: 'gray' },
  error: { label: 'Error', tone: 'gray' },
  not_checked: { label: 'Not checked', tone: 'gray' },
};

// Statuses that count as "evidence collected" for coverage purposes.
export const COMPLETED_CHECK_STATUSES = ['completed', 'no_match', 'match_found'];

export const SEVERITY = {
  critical: { label: 'Critical', tone: 'red', rank: 5 },
  high: { label: 'High', tone: 'orange', rank: 4 },
  medium: { label: 'Medium', tone: 'amber', rank: 3 },
  low: { label: 'Low', tone: 'blue', rank: 2 },
  info: { label: 'Info', tone: 'gray', rank: 1 },
};

export const FINDING_CATEGORY = {
  confirmed: {
    label: 'Confirmed findings',
    description: 'Returned by an external threat intelligence source or verified directly.',
  },
  heuristic: {
    label: 'Heuristic indicators',
    description: 'Patterns associated with risk. Suspicious on their own, not proof of malicious activity.',
  },
  weakness: {
    label: 'Security weaknesses',
    description: 'Configuration gaps. These indicate weaker security, not phishing.',
  },
  informational: {
    label: 'Informational',
    description: 'Context collected during the investigation.',
  },
};

export const STEP_STATUS = ['pending', 'running', 'completed', 'failed', 'skipped'];

export const DEFAULT_STEPS = {
  url: [
    { key: 'submission', label: 'Submission received' },
    { key: 'investigation', label: 'URL investigation' },
    { key: 'threat_intel', label: 'Threat intelligence analysis' },
    { key: 'tls_security', label: 'TLS and security assessment' },
    { key: 'risk_report', label: 'Risk assessment and report' },
  ],
  message: [
    { key: 'submission', label: 'Submission received' },
    { key: 'investigation', label: 'Message investigation' },
    { key: 'threat_intel', label: 'Threat intelligence analysis' },
    { key: 'tls_security', label: 'TLS and security assessment' },
    { key: 'risk_report', label: 'Risk assessment and report' },
  ],
};

export const TACTICS = {
  urgency: 'Urgency',
  threat: 'Threatening language',
  impersonation: 'Impersonation',
  fake_reward: 'Fake reward',
  account_suspension: 'Account suspension threat',
  otp_request: 'OTP request',
  password_request: 'Password request',
  payment_request: 'Payment request',
  suspicious_link: 'Suspicious link',
  social_engineering: 'Social engineering',
};

export const TLS_NOTICE =
  'A valid TLS certificate protects the connection. It does not guarantee that the website itself is legitimate or safe.';

export const PRIVACY_WARNING = 'Never paste passwords, OTPs, private keys, or seed phrases.';

export const SAMPLE_URLS = [
  {
    id: 'legit',
    label: 'Legitimate website',
    value: 'https://example.com',
    hint: 'IANA reserved example domain',
  },
  {
    id: 'suspicious',
    label: 'Suspicious URL',
    value: 'http://paypa1-account-verify.secure-login.example/signin?session=8f2a1c&redirect=confirm',
    hint: 'Uses reserved .example TLD — never resolves',
  },
  {
    id: 'gsb-test',
    label: 'Known malicious test indicator',
    value: 'https://testsafebrowsing.appspot.com/s/phishing.html',
    hint: "Google's official Safe Browsing test page",
  },
];

export const SAMPLE_MESSAGES = [
  {
    id: 'phishing',
    label: 'Suspicious phishing message',
    value:
      'URGENT: Your SBI account has been suspended due to unusual activity. Verify your identity within 24 hours or your account will be permanently blocked. Click http://sbi-kyc-update.example/verify and enter your OTP and password to restore access. Congratulations, you are also eligible for a cashback reward of Rs 5,000!',
  },
  {
    id: 'legit',
    label: 'Legitimate message',
    value:
      'Hi Riya, the team sync has moved to 4 PM tomorrow in the 3rd floor meeting room. The agenda is in the shared drive as usual. See you there!',
  },
];

// Threat categories shared by the Threat Feed and Community reports.
export const THREAT_CATEGORIES = {
  phishing: 'Phishing',
  scam: 'Scam / fraud',
  malware: 'Malware',
  impersonation: 'Impersonation',
  fake_shop: 'Fake shop',
  investment_fraud: 'Investment fraud',
  other: 'Other',
};

// Community report lifecycle. A community report is NEVER a confirmed classification by itself.
export const COMMUNITY_STATUS = {
  pending_review: { label: 'Pending review', tone: 'amber' },
  under_review: { label: 'Under review', tone: 'blue' },
  validated: { label: 'Community validated', tone: 'cyan' },
  disputed: { label: 'Disputed', tone: 'orange' },
  rejected: { label: 'Rejected', tone: 'gray' },
};

export const TX_STATUS = {
  confirmed: { label: 'On-chain · confirmed', tone: 'cyan' },
  pending: { label: 'On-chain · pending', tone: 'amber' },
  failed: { label: 'Registration failed', tone: 'red' },
};

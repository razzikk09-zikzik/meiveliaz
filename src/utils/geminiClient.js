// Direct browser calls to Gemini — fallback when the backend is unreachable
// (e.g. Render free-tier cold start). The heuristic engine + blocklists in
// src/utils/analyze.js still run locally, so the app stays functional.
//
// SECURITY NOTE: a key in VITE_GEMINI_API_KEY is visible in the page bundle.
// Acceptable for a prototype; rotate it if quota is abused. Never put other
// service keys here — VirusTotal/Neo4j/Supabase must stay server-side.
const MODEL = import.meta.env.VITE_GEMINI_MODEL || 'gemini-3.5-flash-lite';
const KEY = import.meta.env.VITE_GEMINI_API_KEY || '';

const TEXT_PROMPT = `You are a scam-detection analyst for MEYVIZHI, an app protecting people in South Chennai, India.
Analyze the following message (it may be English, Tamil, Tanglish or a mix) for scam indicators:
scam intent, phishing, impersonation of banks/government/companies, urgency pressure, requests for OTP/PIN/CVV,
payment requests, social engineering, suspicious instructions, suspicious domain naming.

Respond ONLY with JSON in exactly this shape:
{"risk_score": <int 0-100>, "classification": "SAFE"|"SUSPICIOUS"|"SCAM", "confidence": <float 0-1>,
 "signals": ["<short signal name>", ...], "explanation": "<one or two sentences>"}

Message to analyze:
`;

const IMAGE_PROMPT = `You are a scam-detection analyst for MEYVIZHI, an app protecting people in South Chennai, India.
The attached image is a screenshot (SMS, WhatsApp chat, email, website or payment screen) that a user wants checked.
Analyze every visible element: sender, message text, links, phone numbers, UPI IDs, QR codes, payment requests, urgency, impersonation.
The text may be in Tamil, English or Tanglish.

Respond ONLY with JSON in exactly this shape:
{"transcribed_text": "<transcribe ALL visible text exactly as shown>",
 "risk_score": <int 0-100>, "classification": "SAFE"|"SUSPICIOUS"|"SCAM", "confidence": <float 0-1>,
 "signals": ["<short signal name>", ...], "explanation": "<one or two sentences>"}
`;

export function geminiConfigured() {
  return Boolean(KEY);
}

async function generate(parts, timeoutMs = 45000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': KEY },
        body: JSON.stringify({
          contents: [{ parts }],
          generationConfig: { responseMimeType: 'application/json', temperature: 0.1, maxOutputTokens: 1024 },
        }),
        signal: controller.signal,
      },
    );
    if (!res.ok) throw new Error(`Gemini error ${res.status}`);
    const data = await res.json();
    return JSON.parse(data.candidates[0].content.parts[0].text);
  } finally {
    clearTimeout(timer);
  }
}

function toResult(parsed) {
  const signals = (parsed.signals || []).map((s) => {
    if (typeof s === 'string') {
      return { key: s.toLowerCase().replace(/\s+/g, '_'), title: s, detail: 'AI signal' };
    }
    const name = String((s && s.name) || 'Signal').toLowerCase();
    return { key: name.replace(/\s+/g, '_'), title: name.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()), detail: (s && s.detail) || 'AI signal' };
  });
  return {
    score: Math.max(0, Math.min(100, Math.round(parsed.risk_score || 0))),
    verdict: String(parsed.classification || 'SUSPICIOUS').toLowerCase(),
    signals,
    explanation: parsed.explanation || '',
    urls: [],
    similarReports: null,
    recommendations: null,
  };
}

export async function geminiAnalyzeText(text) {
  if (!KEY) throw new Error('Gemini fallback not configured');
  const parsed = await generate([{ text: TEXT_PROMPT + text }]);
  return toResult(parsed);
}

// Resize a screenshot in the browser and return a data URL (max 1280px JPEG).
export async function fileToResizedDataUrl(file) {
  try {
    const bitmap = await createImageBitmap(file);
    const maxDim = 1280;
    const scale = Math.min(1, maxDim / Math.max(bitmap.width, bitmap.height));
    if (scale >= 1 && file.size < 1.5 * 1024 * 1024) {
      return await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    }
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(bitmap.width * scale);
    canvas.height = Math.round(bitmap.height * scale);
    canvas.getContext('2d').drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    return canvas.toDataURL('image/jpeg', 0.85);
  } catch {
    // Browser cannot decode it (e.g. some HEIC files) — read raw
    return await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }
}

export async function geminiAnalyzeImage(file) {
  if (!KEY) throw new Error('Gemini fallback not configured');
  const dataUrl = await fileToResizedDataUrl(file);
  const m = /^data:([^;]+);base64,(.*)$/.exec(dataUrl);
  const mime = (m && m[1]) || 'image/jpeg';
  const data = (m && m[2]) || '';
  const parsed = await generate([{ text: IMAGE_PROMPT }, { inline_data: { mime_type: mime, data } }]);
  return { ...toResult(parsed), ocrText: parsed.transcribed_text || '' };
}

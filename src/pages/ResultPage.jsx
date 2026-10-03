import { useLocation, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';

export default function ResultPage() {
  const location = useLocation();
  const text = location.state?.text || '';
  const [result, setResult] = useState(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    if (!text) return;
    const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    fetch(`${apiUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    })
      .then(res => {
        if (!res.ok) throw new Error('API Error');
        return res.json();
      })
      .then(data => setResult(data))
      .catch(err => {
        console.error(err);
        setError(true);
      });
  }, [text]);

  return (
    <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      <div style={{ background: '#ffffff', border: '1px solid #E6EAF2', borderRadius: '0.75rem', padding: '1.5rem', textAlign: 'center' }}>
        <h1 style={{ fontFamily: "var(--font-head)", fontSize: '1.5rem', marginBottom: '1rem' }}>
          {error ? 'Service Unavailable' : 'Checking your message...'}
        </h1>
        {error ? (
          <div style={{ color: '#DC2626', marginBottom: '1.5rem', padding: '1rem', background: '#FEE2E2', borderRadius: '0.5rem', fontSize: '16px' }}>
            Could not reach the analysis servers. Please check your connection and try again later.
          </div>
        ) : (
          <p style={{ fontFamily: "var(--font-body)", color: '#64748b', marginBottom: '1.5rem', wordBreak: 'break-word', fontSize: '16px' }}>
            {result ? 'Analysis complete.' : text}
          </p>
        )}
        <Link to="/" style={{ color: '#2563EB', textDecoration: 'none', fontWeight: '600', display: 'inline-flex', minHeight: '48px', alignItems: 'center', justifyContent: 'center' }}>
          ← Back to Home
        </Link>
      </div>
    </div>
  );
}

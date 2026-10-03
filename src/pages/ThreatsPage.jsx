// src/pages/ThreatsPage.jsx
import ScamMap from '../components/ScamMap';
import { scamCards } from '../data/mock';

export default function ThreatsPage() {
  return (
    <div style={{ padding: '1rem', paddingBottom: '2rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div>
        <h1 style={{ fontFamily: "var(--font-head)", fontSize: '1.5rem', fontWeight: 800, marginBottom: '0.25rem' }}>Active threats</h1>
        <p style={{ color: '#475569', fontSize: '0.875rem' }}>What's happening in South Chennai right now.</p>
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', overflowX: 'auto', paddingBottom: '0.5rem', scrollbarWidth: 'none' }}>
        <button style={{ padding: '0.375rem 0.75rem', background: '#2563EB', color: '#fff', borderRadius: '1rem', border: 'none', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>Bank KYC</button>
        <button style={{ padding: '0.375rem 0.75rem', background: '#fff', color: '#475569', borderRadius: '1rem', border: '1px solid #E6EAF2', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>Courier</button>
        <button style={{ padding: '0.375rem 0.75rem', background: '#fff', color: '#475569', borderRadius: '1rem', border: '1px solid #E6EAF2', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>UPI</button>
        <button style={{ padding: '0.375rem 0.75rem', background: '#fff', color: '#475569', borderRadius: '1rem', border: '1px solid #E6EAF2', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>Job offer</button>
        <button style={{ padding: '0.375rem 0.75rem', background: '#fff', color: '#475569', borderRadius: '1rem', border: '1px solid #E6EAF2', fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>Fake link</button>
      </div>

      <div style={{ height: '38vh', position: 'relative', borderRadius: '0.5rem', overflow: 'hidden', border: '1px solid #E6EAF2', zIndex: 0 }}>
        <ScamMap />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {scamCards.map((card) => {
          const isHigh = card.risk === 'high';
          const bgTint = isHigh ? '#FFF5F5' : '#FFFBEB';
          const iconColor = isHigh ? 'invert(16%) sepia(91%) saturate(7351%) hue-rotate(358deg) brightness(94%) contrast(114%)' : 'invert(52%) sepia(61%) saturate(3065%) hue-rotate(1deg) brightness(102%) contrast(105%)';

          return (
            <div key={card.id} style={{ border: '1px solid #E6EAF2', borderRadius: '0.5rem', background: bgTint, padding: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <img src={card.iconUrl} alt="" style={{ width: '2rem', height: '2rem', filter: iconColor }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <h3 style={{ fontFamily: "var(--font-head)", fontWeight: '800', fontSize: '0.9375rem', color: '#0f172a', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{card.title}</h3>
                <p style={{ fontSize: '0.8125rem', color: '#475569', marginTop: '0.125rem' }}>{card.desc}</p>
              </div>
              <svg width="1rem" height="1rem" viewBox="0 0 24 24" fill="none" stroke="#2563EB" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}><polyline points="9 18 15 12 9 6"/></svg>
            </div>
          );
        })}
      </div>
    </div>
  );
}

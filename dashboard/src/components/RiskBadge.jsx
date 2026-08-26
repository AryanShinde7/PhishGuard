// src/components/RiskBadge.jsx

export default function RiskBadge({ level }) {
  const map = {
    'HIGH RISK':  { cls: 'high', icon: '⛔', label: 'High Risk' },
    'SUSPICIOUS': { cls: 'susp', icon: '⚠️', label: 'Suspicious' },
    'SAFE':       { cls: 'safe', icon: '✓',  label: 'Safe' },
  };
  const { cls, icon, label } = map[level] || map['SAFE'];
  return (
    <span className={`risk-badge ${cls}`}>
      {icon} {label}
    </span>
  );
}

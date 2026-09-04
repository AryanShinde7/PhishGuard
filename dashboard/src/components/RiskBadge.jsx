// src/components/RiskBadge.jsx
import { ShieldX, TriangleAlert, ShieldCheck } from 'lucide-react';

const BADGE_MAP = {
  'HIGH RISK':  { cls: 'high', Icon: ShieldX,       label: 'High Risk' },
  'SUSPICIOUS': { cls: 'susp', Icon: TriangleAlert,  label: 'Suspicious' },
  'SAFE':       { cls: 'safe', Icon: ShieldCheck,    label: 'Safe' },
};

export default function RiskBadge({ level }) {
  const { cls, Icon, label } = BADGE_MAP[level] || BADGE_MAP['SAFE'];
  return (
    <span className={`risk-badge ${cls}`}>
      <Icon size={11} strokeWidth={2.5} />
      {label}
    </span>
  );
}

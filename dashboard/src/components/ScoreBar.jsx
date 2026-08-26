// src/components/ScoreBar.jsx

export default function ScoreBar({ score }) {
  const color = score > 60 ? '#ff4d6d' : score > 30 ? '#f0b429' : '#22c55e';
  return (
    <div className="score-cell">
      <span className="score-num" style={{ color }}>{score}</span>
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${score}%`, background: color }}
        />
      </div>
    </div>
  );
}

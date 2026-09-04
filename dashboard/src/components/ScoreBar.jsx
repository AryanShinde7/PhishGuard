// src/components/ScoreBar.jsx

export default function ScoreBar({ score }) {
  const color = score > 60 ? '#DC3B3B' : score > 30 ? '#D99000' : '#16A477';
  return (
    <div className="score-cell">
      <span className="score-num" style={{ color }}>{score}</span>
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${Math.min(score, 100)}%`, background: color }}
        />
      </div>
    </div>
  );
}

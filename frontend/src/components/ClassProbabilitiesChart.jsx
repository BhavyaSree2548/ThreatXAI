import React, { useState } from "react";

export default function ClassProbabilitiesChart({ probabilities, predictedClass }) {
  const [showAllClasses, setShowAllClasses] = useState(false);

  if (!probabilities || Object.keys(probabilities).length === 0) {
    return null;
  }

  // Sort classes by probability descending
  const sortedClasses = Object.entries(probabilities).sort((a, b) => b[1] - a[1]);
  const displayedClasses = showAllClasses ? sortedClasses : sortedClasses.slice(0, 5);

  return (
    <div className="prob-chart-card">
      <div className="prob-chart-header">
        <div>
          <h4 className="prob-chart-title">15-Class Probability Distribution</h4>
          <p className="prob-chart-subtitle">Raw Softmax probability outputs from LightGBM</p>
        </div>
        <button
          className="prob-toggle-btn"
          onClick={() => setShowAllClasses(!showAllClasses)}
        >
          {showAllClasses ? "Top 5 Only" : "View All 15 Classes"}
        </button>
      </div>

      <div className="prob-bars-list">
        {displayedClasses.map(([cls, prob]) => {
          const isWinner = cls === predictedClass;
          const probPercent = (prob * 100).toFixed(prob < 0.01 && prob > 0 ? 4 : 2);
          const widthPercent = Math.max(2, Math.min(100, prob * 100));

          return (
            <div key={cls} className={`prob-row ${isWinner ? "winner-row" : ""}`}>
              <div className="prob-label-group">
                <span className="prob-class-name" title={cls}>
                  {isWinner && <span className="winner-badge">PREDICTED</span>}
                  {cls}
                </span>
                <span className="prob-percent-val">{probPercent}%</span>
              </div>
              <div className="prob-bar-container">
                <div
                  className={`prob-bar-fill ${isWinner ? (cls === "BENIGN" ? "benign-fill" : "threat-fill") : "neutral-fill"}`}
                  style={{ width: `${widthPercent}%` }}
                ></div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

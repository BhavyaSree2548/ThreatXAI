import React, { useState } from "react";

export default function ShapVisualizer({ explanation, supporting, opposing, summary }) {
  const [showAll, setShowAll] = useState(false);

  const displayedList = showAll ? explanation : (explanation || []).slice(0, 6);
  const maxAbsShap = Math.max(
    ...(explanation || []).map((f) => Math.abs(f.shap_value)),
    0.001
  );

  return (
    <div className="shap-container">
      <div className="shap-header">
        <div>
          <h3 className="shap-title">WHY DID THE MODEL MAKE THIS PREDICTION?</h3>
          <p className="shap-subtitle">
            SHAP (SHapley Additive exPlanations) attribution values calculated by TreeExplainer for the trained LightGBM model.
          </p>
        </div>
        <span className="shap-badge">TreeExplainer Active</span>
      </div>

      {/* Narrative Summary Callout */}
      {summary && (
        <div className="shap-summary-box">
          <span className="summary-icon">💡</span>
          <p className="summary-text">{summary}</p>
        </div>
      )}

      {/* Horizontal Factor Attribution Bars */}
      <div className="shap-factors-grid">
        <div className="shap-factors-column">
          <div className="factors-column-header supporting">
            <span className="factor-pill positive">Supporting Prediction (+ Impact)</span>
            <span className="factor-count">{supporting?.length || 0} Features</span>
          </div>

          <div className="factor-bars-list">
            {(supporting && supporting.length > 0) ? (
              supporting.slice(0, showAll ? 10 : 5).map((f, idx) => {
                const widthPercent = Math.min(100, Math.max(8, (Math.abs(f.shap_value) / maxAbsShap) * 100));
                return (
                  <div key={idx} className="factor-row">
                    <div className="factor-meta">
                      <span className="factor-name" title={f.feature}>{f.feature.trim()}</span>
                      <span className="factor-val">Val: {typeof f.value === "number" ? f.value.toFixed(2) : f.value}</span>
                    </div>
                    <div className="factor-bar-track">
                      <div
                        className="factor-bar positive"
                        style={{ width: `${widthPercent}%` }}
                      ></div>
                    </div>
                    <span className="factor-shap-score pos">+{f.shap_value.toFixed(4)}</span>
                  </div>
                );
              })
            ) : (
              <p className="empty-factor-note">No strong positive supporting features.</p>
            )}
          </div>
        </div>

        <div className="shap-factors-column">
          <div className="factors-column-header opposing">
            <span className="factor-pill negative">Opposing Prediction (- Impact)</span>
            <span className="factor-count">{opposing?.length || 0} Features</span>
          </div>

          <div className="factor-bars-list">
            {(opposing && opposing.length > 0) ? (
              opposing.slice(0, showAll ? 10 : 5).map((f, idx) => {
                const widthPercent = Math.min(100, Math.max(8, (Math.abs(f.shap_value) / maxAbsShap) * 100));
                return (
                  <div key={idx} className="factor-row">
                    <div className="factor-meta">
                      <span className="factor-name" title={f.feature}>{f.feature.trim()}</span>
                      <span className="factor-val">Val: {typeof f.value === "number" ? f.value.toFixed(2) : f.value}</span>
                    </div>
                    <div className="factor-bar-track">
                      <div
                        className="factor-bar negative"
                        style={{ width: `${widthPercent}%` }}
                      ></div>
                    </div>
                    <span className="factor-shap-score neg">{f.shap_value.toFixed(4)}</span>
                  </div>
                );
              })
            ) : (
              <p className="empty-factor-note">No strong opposing features.</p>
            )}
          </div>
        </div>
      </div>

      {/* Toggle View More */}
      {explanation && explanation.length > 6 && (
        <div className="shap-actions">
          <button
            className="secondary-btn small-btn"
            onClick={() => setShowAll(!showAll)}
          >
            {showAll ? "▲ Show Top Factors Only" : `▼ View All Top 10 Ranked Features`}
          </button>
        </div>
      )}
    </div>
  );
}

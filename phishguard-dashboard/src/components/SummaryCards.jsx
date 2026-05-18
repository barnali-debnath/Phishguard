


function SummaryCards({ totalScans, phishingCount, safeCount }) {
  return (
    <div className="summary-grid">
      <div className="card summary-card">
        <h3>Total Scans</h3>
        <p>{totalScans}</p>
      </div>

      <div className="card summary-card danger">
        <h3>Phishing</h3>
        <p>{phishingCount}</p>
      </div>

      <div className="card summary-card safe">
        <h3>Safe</h3>
        <p>{safeCount}</p>
      </div>
    </div>
  );
}

export default SummaryCards;
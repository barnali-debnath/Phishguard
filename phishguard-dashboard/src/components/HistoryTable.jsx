import generatePdfReport from "../utils/generatePdfReport";
function HistoryTable({ data }) {
  return (
    <div className="table-container">
      <h2>Scan History</h2>

      <table>
        <thead>
          <tr>
            <th>URL</th>
            <th>Result</th>
            <th>Risk Score</th>
            <th>Timestamp</th>
            <th>Report</th>
          </tr>
        </thead>

        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan="4" style={{ textAlign: "center" }}>
                No scans yet.
              </td>
            </tr>
          ) : (
            data.map((item) => (
            <tr key={item.id}>
              <td className="url-cell">{item.url}</td>
              <td>
                <span
                  className={
                    item.prediction.toLowerCase() === "phishing"
                      ? "badge danger"
                      : "badge safe"
                  }
                >
                  {item.prediction.toUpperCase()}
                </span>
              </td>
              <td>{item.risk_score}</td>
              <td>{item.timestamp}</td>
              <td>
                <button
                  onClick={() => generatePdfReport(item)}
                  className="download-btn"
                >
                  Download PDF
                </button>
              </td>
            </tr>
          ))
          )}
        </tbody>
      </table>
    </div>
  );
}

export default HistoryTable;
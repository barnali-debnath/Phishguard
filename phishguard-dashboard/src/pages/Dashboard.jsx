import { useEffect, useState } from "react";
import SummaryCards from "../components/SummaryCards";
import HistoryTable from "../components/HistoryTable";
import RiskChart from "../components/RiskChart";

function Dashboard() {
  const [scanHistory, setScanHistory] = useState([]);

  useEffect(() => {
    // Load existing scan history
    chrome.storage.local.get(["scanHistory"], (data) => {
      setScanHistory(data.scanHistory || []);
    });

    // Listen for updates
    const listener = (changes, areaName) => {
      if (areaName === "local" && changes.scanHistory) {
        setScanHistory(changes.scanHistory.newValue || []);
      }
    };

    chrome.storage.onChanged.addListener(listener);

    return () => {
      chrome.storage.onChanged.removeListener(listener);
    };
  }, []);

  const totalScans = scanHistory.length;

  const phishingCount = scanHistory.filter((item) =>
    item.prediction.toLowerCase().includes("phish")
  ).length;

  const safeCount = totalScans - phishingCount;

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <img
          src="./logo.png"
          alt="PhishGuard Logo"
          className="dashboard-logo"
        />

        <div className="header-text">
          <h1 className="dashboard-title">
            PHISHGUARD DASHBOARD
          </h1>
          <p className="dashboard-subtitle">
            Security analytics and phishing scan history.
          </p>
        </div>
      </div>

      <SummaryCards
        totalScans={totalScans}
        phishingCount={phishingCount}
        safeCount={safeCount}
      />

      <RiskChart
        phishingCount={phishingCount}
        safeCount={safeCount}
      />

      <HistoryTable data={scanHistory} />
    </div>
  );
}

export default Dashboard;


// import { scanHistory } from "../data/mockData";
// import SummaryCards from "../components/SummaryCards";
// import HistoryTable from "../components/HistoryTable";
// import RiskChart from "../components/RiskChart";

// function Dashboard() {
//   const totalScans = scanHistory.length;
//   const phishingCount = scanHistory.filter(
//     (item) => item.prediction === "phishing"
//   ).length;
//   const safeCount = scanHistory.filter(
//     (item) => item.prediction === "safe"
//   ).length;

//   return (
//     <div className  = "dashboard">
//    <div className="dashboard-header">
//   <img
//     src="/logo.png"
//     alt="PhishGuard Logo"
//     className="dashboard-logo"
//   />

//   <div className="header-text">
//     <h1 className="dashboard-title">PHISHGUARD DASHBOARD</h1>
//     <p className="dashboard-subtitle">
//       Security analytics and phishing scan history.
//     </p>
//   </div>
// </div>

//       <SummaryCards
//         totalScans={totalScans}
//         phishingCount={phishingCount}
//         safeCount={safeCount}
//       />

//       <RiskChart
//         phishingCount={phishingCount}
//         safeCount={safeCount}
//       />

//       <HistoryTable data={scanHistory} />
//     </div>
//   );
// }

// export default Dashboard;



// test 
// function Dashboard() {
//   return (
//     <div style={{ background: "#050505", color: "white", minHeight: "100vh", padding: "40px" }}>
//       <h1 style={{ color: "#6529EE" }}>PHISHGUARD DASHBOARD</h1>
//       <p>Dashboard page is loading.</p>
//     </div>
//   );
// }

// export default Dashboard;

//test 3
// import SummaryCards from "../components/SummaryCards";

// function Dashboard() {
//   return (
//     <div
//       style={{
//         background: "#050505",
//         color: "white",
//         minHeight: "100vh",
//         padding: "40px",
//       }}
//     >
//       <h1 style={{ color: "#6529EE" }}>PHISHGUARD DASHBOARD</h1>
//       <p>Dashboard page is loading.</p>

//       <SummaryCards
//         totalScans={4}
//         phishingCount={2}
//         safeCount={2}
//       />
//     </div>
//   );
// }

// export default Dashboard;   


// test 4
// import SummaryCards from "../components/SummaryCards";
// import HistoryTable from "../components/HistoryTable";
// import { scanHistory } from "../data/mockData";

// function Dashboard() {
//   const totalScans = scanHistory.length;

//   const phishingCount = scanHistory.filter(
//     (item) => item.prediction === "phishing"
//   ).length;

//   const safeCount = scanHistory.filter(
//     (item) => item.prediction === "safe"
//   ).length;

//   return (
//     <div className="dashboard">
//       <h1 className="dashboard-title">PHISHGUARD DASHBOARD</h1>
//       <p className="dashboard-subtitle">
//         Security analytics and phishing scan history.
//       </p>

//       <SummaryCards
//         totalScans={totalScans}
//         phishingCount={phishingCount}
//         safeCount={safeCount}
//       />

//       <HistoryTable data={scanHistory} />
//     </div>
//   );
// }

// export default Dashboard;
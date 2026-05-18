//final
function RiskChart({ phishingCount, safeCount }) {
  return (
    <div className="chart-card">
      <h2>Detection Distribution</h2>

      <p>
        <strong>Phishing Detected:</strong> {phishingCount}
      </p>

      <p>
        <strong>Safe Websites:</strong> {safeCount}
      </p>
    </div>
  );
}

export default RiskChart;


// //for now
// import {
//   PieChart,
//   Pie,
//   Cell,
//   Tooltip,
//   Legend,
// } from "recharts";

// function RiskChart({ phishingCount, safeCount }) {
//   const data = [
//     { name: "Phishing", value: phishingCount },
//     { name: "Safe", value: safeCount },
//   ];

//   const COLORS = ["#ff4d4d", "#22c55e"];

//   return (
//     <div className="chart-card">
//       <h2>Detection Distribution</h2>

//       <PieChart width={500} height={300}>
//         <Pie
//           data={data}
//           dataKey="value"
//           cx={250}
//           cy={150}
//           outerRadius={100}
//           label
//         >
//           {data.map((entry, index) => (
//             <Cell
//               key={entry.name}
//               fill={COLORS[index]}
//             />
//           ))}
//         </Pie>

//         <Tooltip />
//         <Legend />
//       </PieChart>
//     </div>
//   );
// }

// export default RiskChart;









//final?
// import {
//   PieChart,
//   Pie,
//   Cell,
//   Tooltip,
//   ResponsiveContainer,
//   Legend,
// } from "recharts";

// function RiskChart({ phishingCount, safeCount }) {
//   const data = [
//     { name: "Phishing", value: phishingCount },
//     { name: "Safe", value: safeCount },
//   ];

//   const COLORS = ["#ff4d4d", "#22c55e"];

//   return (
//     <div className="chart-card">
//       <h2>Detection Distribution</h2>

//       <ResponsiveContainer width="100%" height={300}>
//         <PieChart>
//           <Pie
//             data={data}
//             cx="50%"
//             cy="50%"
//             outerRadius={100}
//             dataKey="value"
//             label
//           >
//             {data.map((entry, index) => (
//               <Cell key={index} fill={COLORS[index]} />
//             ))}
//           </Pie>
//           <Tooltip />
//           <Legend />
//         </PieChart>
//       </ResponsiveContainer>
//     </div>
//   );
// }

// export default RiskChart;




//testing
// function RiskChart() {
//   return (
//     <div className="chart-card">
//       <h2>Detection Distribution</h2>
//       <p>Chart component loaded successfully.</p>
//     </div>
//   );
// }

// export default RiskChart;



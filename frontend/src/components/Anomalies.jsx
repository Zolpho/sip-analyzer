const severity = (a) => {
  if (a.includes("500") || a.includes("Network down")) return "high";
  if (a.includes("SSRC") || a.includes("charging") || a.includes("quota")) return "medium";
  return "low";
};
const COLORS = {
  high:   "bg-red-50 border-red-300 text-red-800 dark:bg-red-900/20 dark:border-red-700 dark:text-red-300",
  medium: "bg-yellow-50 border-yellow-300 text-yellow-800 dark:bg-yellow-900/20 dark:border-yellow-700 dark:text-yellow-300",
  low:    "bg-gray-50 border-gray-300 text-gray-700 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-300",
};
const ICONS = { high: "🔴", medium: "🟡", low: "🔵" };

export default function Anomalies({ data }) {
  if (!data?.length) return (
    <div className="flex items-center gap-2 text-green-600 dark:text-green-400 text-sm">
      <span>✅</span><span>No anomalies detected.</span>
    </div>
  );
  return (
    <div className="space-y-2">
      {data.map((a, i) => {
        const sev = severity(a);
        return (
          <div key={i} className={`flex items-start gap-3 p-3 rounded-lg border text-sm ${COLORS[sev]}`}>
            <span>{ICONS[sev]}</span>
            <span className="font-mono text-xs leading-relaxed">{a}</span>
          </div>
        );
      })}
    </div>
  );
}


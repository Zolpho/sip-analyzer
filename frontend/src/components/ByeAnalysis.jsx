export default function ByeAnalysis({ data }) {
  if (!data) return <p className="text-gray-400 text-sm">No BYE detected in this log.</p>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <p className="text-xs text-red-500 dark:text-red-400 font-semibold uppercase mb-1">BYE Sender</p>
          <p className="text-lg font-bold text-red-700 dark:text-red-300">{data.sender}</p>
          <p className="text-sm font-mono text-red-600 dark:text-red-400">{data.sender_number}</p>
        </div>
        <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-4">
          <p className="text-xs text-orange-500 dark:text-orange-400 font-semibold uppercase mb-1">Reason Header</p>
          <p className="text-sm text-orange-700 dark:text-orange-300">{data.reason || "None (user hang-up)"}</p>
        </div>
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
          <p className="text-xs text-yellow-600 dark:text-yellow-400 font-semibold uppercase mb-2">Evidence</p>
          <ul className="space-y-1">
            {data.evidence?.map((e, i) => (
              <li key={i} className="text-xs text-yellow-800 dark:text-yellow-300 flex gap-1">
                <span>•</span><span>{e}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
      <div>
        <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-2">Raw BYE Snippet</p>
        <pre className="bg-gray-900 text-green-400 text-xs p-4 rounded-lg overflow-x-auto leading-relaxed">
          {data.raw_snippet}
        </pre>
      </div>
    </div>
  );
}


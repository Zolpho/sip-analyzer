export default function Participants({ data }) {
  if (!data?.length) return <p className="text-gray-400 text-sm">No participants detected.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-100 dark:bg-gray-700 text-left">
            {["Role","Number","IMSI","Device","IP"].map(h => (
              <th key={h} className="px-4 py-2 font-semibold text-gray-600 dark:text-gray-300">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((p, i) => (
            <tr key={i} className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
              <td className="px-4 py-2">
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                  p.role?.includes("Caller") ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                  : p.role?.includes("Callee") ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                  : "bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300"
                }`}>{p.role || "—"}</span>
              </td>
              <td className="px-4 py-2 font-mono font-semibold">{p.number || "—"}</td>
              <td className="px-4 py-2 font-mono text-xs text-gray-500 dark:text-gray-400">{p.imsi || "—"}</td>
              <td className="px-4 py-2 text-xs text-gray-600 dark:text-gray-300">{p.device || "—"}</td>
              <td className="px-4 py-2 font-mono text-xs text-gray-500 dark:text-gray-400">{p.ip || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


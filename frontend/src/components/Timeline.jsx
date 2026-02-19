const METHOD_COLOR = {
  INVITE: "method-INVITE", BYE: "method-BYE", CANCEL: "method-CANCEL",
  REGISTER: "method-REGISTER", PRACK: "method-PRACK", NOTIFY: "method-NOTIFY",
  CODEC: "method-CODEC", INTERNAL: "method-INTERNAL",
};
const getMethodClass = (m) => {
  if (m.startsWith("200")) return "method-200";
  if (m.startsWith("180")) return "method-180";
  if (m.startsWith("183")) return "method-183";
  if (m.startsWith("100")) return "method-100";
  if (m.startsWith("5"))   return "method-500";
  return METHOD_COLOR[m] || "method-INTERNAL";
};

export default function Timeline({ events }) {
  if (!events?.length) return <p className="text-gray-400 text-sm">No timeline events found.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-gray-100 dark:bg-gray-700 text-left">
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300 whitespace-nowrap">#</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300 whitespace-nowrap">Timestamp</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">Dir</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">Method</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300 w-full">Description</th>
          </tr>
        </thead>
        <tbody>
          {events.map((ev, i) => (
            <tr key={i} className={`border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50 ${i % 2 === 0 ? "" : "bg-gray-50/50 dark:bg-gray-800/50"}`}>
              <td className="px-3 py-1.5 text-gray-400">{i + 1}</td>
              <td className="px-3 py-1.5 font-mono text-gray-500 dark:text-gray-400 whitespace-nowrap">{ev.timestamp.replace("_", " ")}</td>
              <td className="px-3 py-1.5">
                <span className={`dir-${ev.direction} text-xs font-mono`}>{ev.direction}</span>
              </td>
              <td className="px-3 py-1.5">
                <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${getMethodClass(ev.method)}`}>
                  {ev.method}
                </span>
              </td>
              <td className="px-3 py-1.5 text-gray-700 dark:text-gray-300 font-mono">{ev.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


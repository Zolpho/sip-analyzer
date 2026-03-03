export default function Participants({ data }) {
  if (!data?.length) return <p className="text-gray-400 text-sm">No participants found.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-gray-100 dark:bg-gray-700 text-left">
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">Role</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">Number</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">IMSI</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">Device</th>
            <th className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300">IP</th>
          </tr>
        </thead>
        <tbody>
          {data.map((p, i) => (
            <tr key={i} className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
              <td className="px-3 py-2">
                <span className="bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 px-2 py-0.5 rounded text-xs font-semibold">
                  {p.role || 'Unknown'}
                </span>
              </td>
              <td className="px-3 py-2 font-mono text-gray-800 dark:text-gray-200">{p.number || '—'}</td>
              <td className="px-3 py-2 font-mono text-gray-500 dark:text-gray-400">{p.imsi  || '—'}</td>
              <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{p.device || '—'}</td>
              <td className="px-3 py-2 font-mono text-gray-500 dark:text-gray-400">{p.ip    || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


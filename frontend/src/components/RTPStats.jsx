export default function RTPStats({ data, sdp }) {
  return (
    <div className="space-y-4">
      {(!data?.length) ? (
        <p className="text-gray-400 text-sm">No RTP stats found.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-gray-100 dark:bg-gray-700 text-left">
                {["Leg","Sent Pkts","Sent Bytes","Recv Pkts","Recv Bytes","Lost","Discarded","Jitter","Codec"].map(h => (
                  <th key={h} className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300 text-xs whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.map((r, i) => (
                <tr key={i} className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-3 py-2 font-mono text-xs">{r.leg}</td>
                  <td className="px-3 py-2">{r.ps}</td>
                  <td className="px-3 py-2">{r.os}</td>
                  <td className="px-3 py-2">{r.pr}</td>
                  <td className="px-3 py-2">{r.or_}</td>
                  <td className={`px-3 py-2 font-semibold ${r.pl !== "0" ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"}`}>{r.pl}</td>
                  <td className="px-3 py-2">{r.pd}</td>
                  <td className="px-3 py-2">{r.ji} ms</td>
                  <td className="px-3 py-2 text-xs text-blue-600 dark:text-blue-400">{r.codec || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {sdp && (
        <div className="mt-4">
          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase mb-2">SDP Negotiation</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[["Offered", sdp.offered], ["Answered", sdp.answered]].map(([label, entries]) => (
              <div key={label} className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                <p className="text-xs font-semibold text-gray-500 mb-2">{label}</p>
                {entries?.map((e, i) => (
                  <div key={i} className="text-xs mb-1">
                    <span className="text-gray-400">{e.ua}: </span>
                    <span className="font-mono text-blue-600 dark:text-blue-300">{e.codecs?.join(", ")}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


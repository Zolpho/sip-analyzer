export default function DataUsage({ data }) {
  if (!data?.length) return (
    <p className="text-gray-400 text-sm">No Diameter charging data found.</p>
  );

  const hasVoice = data.some(d => d.voice_sec_fmt);
  const hasData  = data.some(d => d.total_bytes > 0 || d.in_bytes > 0 || d.out_bytes > 0);

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="bg-gray-100 dark:bg-gray-700 text-left">
            {["IMSI","MSISDN","APN","Service","IP","Session Start","Session End",
              "Input","Output","Total",
              ...(hasVoice ? ["Voice Time"] : []),
              "Requests","Status"
            ].map(h => (
              <th key={h} className="px-3 py-2 font-semibold text-gray-600 dark:text-gray-300 whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((d, i) => (
            <tr key={i} className={`border-b border-gray-100 dark:border-gray-700
              hover:bg-gray-50 dark:hover:bg-gray-700/50
              ${i % 2 === 0 ? '' : 'bg-gray-50/50 dark:bg-gray-800/50'}`}>
              <td className="px-3 py-1.5 font-mono text-gray-500">{d.imsi || '—'}</td>
              <td className="px-3 py-1.5 font-mono font-semibold">{d.msisdn || '—'}</td>
              <td className="px-3 py-1.5">
                <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
                  d.apn === 'chili'    ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300' :
                  d.apn === 'ims'      ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300' :
                  d.apn === 'internet' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' :
                  'bg-gray-100 text-gray-600'
                }`}>{d.apn || '—'}</span>
              </td>
              <td className="px-3 py-1.5 text-gray-500">{d.service || '—'}</td>
              <td className="px-3 py-1.5 font-mono text-gray-400">{d.ip || '—'}</td>
              <td className="px-3 py-1.5 font-mono text-gray-500 whitespace-nowrap">
                {d.start_ts?.replace('_',' ').substring(0,19) || '—'}
              </td>
              <td className="px-3 py-1.5 font-mono text-gray-500 whitespace-nowrap">
                {d.end_ts?.replace('_',' ').substring(0,19) || '—'}
              </td>
              <td className="px-3 py-1.5 text-right">
                {d.in_bytes > 0
                  ? <span className="text-blue-600 dark:text-blue-400">{d.in_bytes_fmt}</span>
                  : <span className="text-gray-300">0 B</span>}
              </td>
              <td className="px-3 py-1.5 text-right">
                {d.out_bytes > 0
                  ? <span className="text-green-600 dark:text-green-400">{d.out_bytes_fmt}</span>
                  : <span className="text-gray-300">0 B</span>}
              </td>
              <td className="px-3 py-1.5 text-right font-semibold">
                {d.total_bytes > 0
                  ? <span className="text-purple-600 dark:text-purple-400">{d.total_bytes_fmt}</span>
                  : <span className="text-gray-300">0 B</span>}
              </td>
              {hasVoice && (
                <td className="px-3 py-1.5 text-center">
                  {d.voice_sec_fmt
                    ? <span className="text-yellow-600 dark:text-yellow-400">{d.voice_sec_fmt}</span>
                    : '—'}
                </td>
              )}
              <td className="px-3 py-1.5 text-center text-gray-400">{d.req_count}</td>
              <td className="px-3 py-1.5">
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                  d.status === 'terminated'
                    ? 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                    : 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                }`}>{d.status}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-3 flex gap-6 text-xs text-gray-500 dark:text-gray-400">
        <span>Total sessions: <strong>{data.length}</strong></span>
        <span>Terminated: <strong>{data.filter(d=>d.status==='terminated').length}</strong></span>
        <span>Total output: <strong className="text-green-600 dark:text-green-400">
          {(()=>{
            let t = data.reduce((a,d)=>a+d.out_bytes,0);
            if(t===0) return '0 B';
            for(const u of ['B','KB','MB','GB']){if(t<1024)return`${t.toFixed(1)} ${u}`;t/=1024;}
            return `${t.toFixed(1)} TB`;
          })()}
        </strong></span>
      </div>
    </div>
  );
}


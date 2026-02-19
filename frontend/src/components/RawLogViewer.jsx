import { useState } from "react";

export default function RawLogViewer({ log }) {
  const [search, setSearch] = useState("");
  const lines = log?.split("\n") || [];
  const filtered = search
    ? lines.filter(l => l.toLowerCase().includes(search.toLowerCase()))
    : lines;

  return (
    <div>
      <div className="mb-3 flex gap-2">
        <input
          type="text" value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter lines..."
          className="border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-1.5 text-sm bg-white dark:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500 w-64"
        />
        {search && (
          <span className="text-xs text-gray-400 self-center">
            {filtered.length} / {lines.length} lines
          </span>
        )}
      </div>
      <pre className="bg-gray-900 text-gray-300 text-xs p-4 rounded-lg overflow-auto max-h-[60vh] leading-relaxed whitespace-pre-wrap">
        {filtered.map((line, i) => {
          const hl = search && line.toLowerCase().includes(search.toLowerCase());
          return (
            <span key={i} className={hl ? "bg-yellow-400/30" : ""}>
              {line}{"\n"}
            </span>
          );
        })}
      </pre>
    </div>
  );
}


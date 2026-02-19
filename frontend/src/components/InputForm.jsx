import { useState, useRef } from "react";

const FLAG_OPTIONS = [
  { value: "+sdp",     label: "SDP Negotiation" },
  { value: "+pgw",     label: "PGW Events"       },
  { value: "+routing", label: "Routing Path"     },
  { value: "+full",    label: "Full Analysis"    },
];

export default function InputForm({ form, setForm, onAnalyze, loading }) {
  const [mode,     setMode]     = useState("paste");
  const [file,     setFile]     = useState(null);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef();

  const toggleFlag = (v) =>
    setForm(f => ({ ...f, flags: f.flags.includes(v) ? f.flags.filter(x => x !== v) : [...f.flags, v] }));

  const handleSubmit = (e) => {
    e.preventDefault();
    if (mode === "file" && file) {
      const fd = new FormData();
      fd.append("file", file);
      if (form.caller)      fd.append("caller",      form.caller);
      if (form.callee)      fd.append("callee",      form.callee);
      if (form.caller_imsi) fd.append("caller_imsi", form.caller_imsi);
      if (form.callee_imsi) fd.append("callee_imsi", form.callee_imsi);
      fd.append("flags", JSON.stringify(form.flags));
      onAnalyze(fd, true);
    } else {
      onAnalyze({ ...form });
    }
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) { setFile(f); setMode("file"); }
  };

  const Field = ({ label, fkey, placeholder }) => (
    <div className="flex flex-col gap-1">
      <label className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide">
        {label}
      </label>
      <input type="text" value={form[fkey]}
        onChange={e => setForm(f => ({ ...f, [fkey]: e.target.value }))}
        placeholder={placeholder}
        className="border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 text-sm
                   bg-white dark:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500"
      />
    </div>
  );

  const canSubmit = !loading && (mode === "paste" ? form.log.trim() : !!file);

  return (
    <form onSubmit={handleSubmit}
      className="bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 p-5">
      <h2 className="text-base font-semibold mb-4 text-gray-700 dark:text-gray-200">Call Parameters</h2>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
        <Field label="Caller Number"  fkey="caller"      placeholder="+41793873549"    />
        <Field label="Callee Number"  fkey="callee"      placeholder="+41792450306"    />
        <Field label="Caller IMSI"    fkey="caller_imsi" placeholder="optional"        />
        <Field label="Callee IMSI"    fkey="callee_imsi" placeholder="228650000101898" />
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        {FLAG_OPTIONS.map(f => (
          <button key={f.value} type="button" onClick={() => toggleFlag(f.value)}
            className={`px-3 py-1 rounded-full text-xs font-medium border transition-colors ${
              form.flags.includes(f.value)
                ? "bg-blue-600 text-white border-blue-600"
                : "bg-white dark:bg-gray-700 text-gray-600 dark:text-gray-300 border-gray-300 dark:border-gray-600 hover:border-blue-400"
            }`}>
            {f.label}
          </button>
        ))}
      </div>

      <div className="flex gap-2 mb-3">
        {["paste","file"].map(m => (
          <button key={m} type="button" onClick={() => setMode(m)}
            className={`px-4 py-1.5 rounded-lg text-sm font-medium border transition-colors ${
              mode === m
                ? "bg-blue-600 text-white border-blue-600"
                : "bg-white dark:bg-gray-700 text-gray-600 dark:text-gray-300 border-gray-300 dark:border-gray-600"
            }`}>
            {m === "paste" ? "📋 Paste Log" : "📁 Upload File"}
          </button>
        ))}
      </div>

      {mode === "paste" ? (
        <textarea value={form.log} onChange={e => setForm(f => ({ ...f, log: e.target.value }))}
          rows={10} placeholder="Paste your YATE SIP log here..."
          className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2
                     text-xs font-mono bg-white dark:bg-gray-900 focus:outline-none
                     focus:ring-2 focus:ring-blue-500 resize-y" />
      ) : (
        <div onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileRef.current.click()}
          className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-colors ${
            dragOver
              ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
              : "border-gray-300 dark:border-gray-600 hover:border-blue-400"
          }`}>
          <input ref={fileRef} type="file" accept=".log,.txt,.sip"
            className="hidden" onChange={e => setFile(e.target.files[0])} />
          {file
            ? <p className="text-green-600 dark:text-green-400 font-medium">✅ {file.name}</p>
            : <p className="text-gray-400 text-sm">Drag & drop .log / .txt file, or click to browse</p>
          }
        </div>
      )}

      <div className="mt-4 flex justify-end">
        <button type="submit" disabled={!canSubmit}
          className="px-6 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50
                     disabled:cursor-not-allowed text-white font-semibold rounded-lg
                     text-sm transition-colors shadow">
          {loading ? "⏳ Analyzing…" : "🔍 Analyze Call"}
        </button>
      </div>
    </form>
  );
}


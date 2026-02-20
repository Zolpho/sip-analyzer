import { useState, useEffect } from "react";
import axios from "axios";
import InputForm    from "./components/InputForm";
import Timeline     from "./components/Timeline";
import Participants from "./components/Participants";
import ByeAnalysis  from "./components/ByeAnalysis";
import RTPStats     from "./components/RTPStats";
import Anomalies    from "./components/Anomalies";
import RawLogViewer from "./components/RawLogViewer";
import ExportBar    from "./components/ExportBar";
import ThemeToggle  from "./components/ThemeToggle";
import DataUsage    from "./components/DataUsage";

const API  = import.meta.env.VITE_API_URL || "";
const TABS = ["Timeline","Participants","BYE Analysis","RTP Stats","Anomalies","Data Usage","Raw Log"];

export default function App() {
  const [dark, setDark] = useState(() => window.matchMedia("(prefers-color-scheme: dark)").matches);
  const [form, setForm] = useState({
    caller:"", callee:"", caller_imsi:"", callee_imsi:"", log:"", flags:[],
  });
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState(null);
  const [tab,     setTab]     = useState("Timeline");

  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark);
  }, [dark]);

  const handleAnalyze = async (payload, isFile = false) => {
    setLoading(true); setError(null); setResult(null);
    try {
      const res = isFile
        ? await axios.post(`${API}/analyze/upload`, payload, { headers:{"Content-Type":"multipart/form-data"} })
        : await axios.post(`${API}/analyze`, payload);
      setResult(res.data);
      setTab("Timeline");
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  const badgeCount = (t) => {
    if (!result) return null;
        const map = { Timeline: result.timeline?.length, Anomalies: result.anomalies?.length,
                  Participants: result.participants?.length, "RTP Stats": result.rtp_stats?.length,
                  "Data Usage": result.data_usage?.length };

    return map[t] ?? null;
  };

  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-blue-900 dark:bg-gray-900 text-white px-6 py-4 flex items-center justify-between shadow-lg">
        <div className="flex items-center gap-3">
          <span className="text-2xl">📞</span>
          <div>
            <h1 className="text-xl font-bold tracking-tight">SIP Call Analyzer</h1>
            <p className="text-blue-300 dark:text-gray-400 text-xs">YATE / IMS Log Analysis Tool</p>
          </div>
        </div>
        <ThemeToggle dark={dark} setDark={setDark} />
      </header>

      <main className="flex-1 p-4 md:p-6 max-w-screen-2xl mx-auto w-full">
        <InputForm form={form} setForm={setForm} onAnalyze={handleAnalyze} loading={loading} />

        {error && (
          <div className="mt-4 p-4 bg-red-100 dark:bg-red-900/50 border border-red-300 dark:border-red-700 rounded-lg text-red-800 dark:text-red-200 text-sm">
            <strong>Error:</strong> {error}
          </div>
        )}

        {result && (
          <div className="mt-6">
            <div className="flex flex-wrap gap-3 mb-4">
              {[["Post-Dial Delay", result.answer_time],
                ["Ring Time",       result.ring_time],
                ["Call Duration",   result.call_duration]
               ].map(([label, val]) => val && (
                <div key={label} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-full px-4 py-1 text-sm shadow-sm">
                  <span className="text-gray-500 dark:text-gray-400">{label}: </span>
                  <span className="font-semibold text-blue-700 dark:text-blue-300">{val}</span>
                </div>
              ))}
            </div>

            <ExportBar formData={form} api={API} />

            <div className="flex flex-wrap gap-1 mt-4 border-b border-gray-200 dark:border-gray-700">
              {TABS.map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className={`px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                    tab === t
                      ? "bg-white dark:bg-gray-800 border border-b-white dark:border-gray-700 dark:border-b-gray-800 text-blue-700 dark:text-blue-300"
                      : "text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
                  }`}>
                  {t}
                  {badgeCount(t) !== null && (
                    <span className="ml-1.5 bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300 text-xs rounded-full px-1.5 py-0.5">
                      {badgeCount(t)}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-b-lg rounded-tr-lg p-4 shadow-sm">
              {tab === "Timeline"     && <Timeline     events={result.timeline} />}
              {tab === "Participants" && <Participants  data={result.participants} />}
              {tab === "BYE Analysis" && <ByeAnalysis  data={result.bye_info} />}
              {tab === "RTP Stats"    && <RTPStats      data={result.rtp_stats} sdp={result.sdp_info} />}
              {tab === "Anomalies"    && <Anomalies     data={result.anomalies} />}
              {tab === "Data Usage"   && <DataUsage     data={result.data_usage} />}
              {tab === "Raw Log"      && <RawLogViewer  log={form.log} />}
            </div>
          </div>
        )}
      </main>

      <footer className="text-center text-xs text-gray-400 dark:text-gray-600 py-3">
        SIP Analyzer · YATE / IMS Log Parser
      </footer>
    </div>
  );
}


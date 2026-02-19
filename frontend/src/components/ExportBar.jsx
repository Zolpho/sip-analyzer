import axios from "axios";

export default function ExportBar({ formData, api }) {
  const download = async (format) => {
    try {
      const res = await axios.post(`${api}/export/${format}`, formData, {
        responseType: "blob",
      });
      const url = URL.createObjectURL(res.data);
      const a = document.createElement("a");
      a.href = url;
      a.download = `sip_analysis.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      alert("Export failed: " + e.message);
    }
  };

  return (
    <div className="flex gap-2">
      <button onClick={() => download("csv")}
        className="px-4 py-1.5 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg transition-colors shadow-sm">
        ⬇️ Export CSV
      </button>
      <button onClick={() => download("pdf")}
        className="px-4 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors shadow-sm">
        ⬇️ Export PDF
      </button>
    </div>
  );
}


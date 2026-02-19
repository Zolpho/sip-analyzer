export default function ThemeToggle({ dark, setDark }) {
  return (
    <button
      onClick={() => setDark(d => !d)}
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-blue-800 dark:bg-gray-700
                 hover:bg-blue-700 dark:hover:bg-gray-600 text-sm text-white transition-colors"
      title="Toggle theme"
    >
      {dark ? "☀️ Light" : "🌙 Dark"}
    </button>
  );
}


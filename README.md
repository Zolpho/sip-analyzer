# SIP Call Log Analyzer

Web-based YATE/IMS SIP log analysis tool.

## Quick Start

```bash
cp .env.example frontend/.env
# Edit frontend/.env and set your VM IP
docker-compose up --build -d
```

Open: http://<vm-ip>:3001

## Ports
- Frontend: 3001
- Backend:  8001

## Features
- Call Flow Timeline with color-coded SIP methods
- Participants table (auto-detected + manual input)
- BYE analysis with evidence
- RTP/media statistics
- Anomaly detection
- PDF + CSV export
- Dark / Light mode
- Paste log or upload file

```
sip-analyzer/
├── docker-compose.yml ✅
├── .env.example       ✅
├── README.md          ✅
├── backend/
│   ├── Dockerfile       ✅
│   ├── requirements.txt ✅
│   ├── main.py          ✅
│   ├── models.py        ✅
│   ├── parser.py        ✅
│   ├── analyzer.py      ✅
│   └── exporter.py      ✅
└── frontend/
    ├── Dockerfile         ✅
    ├── nginx.conf         ✅
    ├── package.json       ✅
    ├── vite.config.js     ✅
    ├── tailwind.config.js ✅
    ├── postcss.config.js  ✅
    ├── index.html         ✅
    └── src/
        ├── main.jsx       ✅
        ├── App.jsx        ✅
        ├── index.css      ✅
        └── components/
            ├── InputForm.jsx    ✅
            ├── Timeline.jsx     ✅
            ├── Participants.jsx ✅
            ├── ByeAnalysis.jsx  ✅
            ├── RTPStats.jsx     ✅
            ├── Anomalies.jsx    ✅
            ├── RawLogViewer.jsx ✅
            ├── ExportBar.jsx    ✅
            └── ThemeToggle.jsx  ✅
            └── DataUsage.jsx    ✅
```

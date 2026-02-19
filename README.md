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

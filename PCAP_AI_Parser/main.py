"""
main.py - PacketParser-AI Web Dashboard entry point.

Usage:
    uv run python main.py
    then open http://localhost:8000
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "pcap_ai_parser.web.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=["src"],
    )

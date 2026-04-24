#!/usr/bin/env python3
"""
TBHM Application Runner
"""

import uvicorn
from src.tbhm.main import app


def main():
    """Run the TBHM application."""
    uvicorn.run(
        "src.tbhm.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
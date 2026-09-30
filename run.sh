#!/usr/bin/env bash

# Resolve the absolute path of this script's directory regardless of where you call it from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# If the virtual environment does not exist, set it up automatically
if [ ! -d "venv" ]; then
    echo "⚙️ Virtual environment not found. Setting it up now..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install streamlit boto3
else
    source venv/bin/activate
fi

echo "🚀 Starting S3 Log Inspector..."
streamlit run app.py

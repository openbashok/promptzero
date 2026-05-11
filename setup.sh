#!/usr/bin/env bash
# Sets up the virtual environment and downloads the spaCy NLP model.
# Usage:
#   ./setup.sh          → installs en_core_web_lg  (best accuracy, ~560 MB)
#   ./setup.sh small    → installs en_core_web_sm  (faster, ~12 MB)

set -e

MODEL="en_core_web_lg"
if [ "${1}" = "small" ]; then
    MODEL="en_core_web_sm"
fi

echo "Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "Downloading spaCy model: ${MODEL}..."
python -m spacy download "${MODEL}"

echo ""
echo "Setup complete."
echo "Next steps:"
echo "  cp .env.example .env   # then add your ANTHROPIC_API_KEY"
echo "  source .venv/bin/activate"
echo "  python main.py"

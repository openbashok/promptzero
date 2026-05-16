#!/usr/bin/env bash
# Sets up the virtual environment and downloads the spaCy NLP models for
# English + Spanish so PromptZero can detect PERSON / ORGANIZATION across
# AR, CL, CO, ES, MX, PE, UY, and English corpora.
#
# Usage:
#   ./setup.sh             → downloads *_lg models (best accuracy, ~560 MB each)
#   ./setup.sh medium      → downloads *_md models (~40 MB each)
#   ./setup.sh small       → downloads *_sm models (~12 MB each, fastest)
#   ./setup.sh en-only     → downloads only the English large model

set -e

SIZE="lg"
LANGS="en es"
case "${1:-}" in
    medium)  SIZE="md" ;;
    small)   SIZE="sm" ;;
    en-only) LANGS="en" ;;
    "")      ;;  # default
    *)       echo "unknown option: $1"; exit 1 ;;
esac

echo "Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

for lang in $LANGS; do
    case "$lang" in
        en) model="en_core_web_${SIZE}" ;;
        es) model="es_core_news_${SIZE}" ;;
    esac
    echo "Downloading spaCy model: ${model}..."
    python -m spacy download "${model}"
done

echo ""
echo "Setup complete."
echo "Next steps:"
echo "  cp .env.example .env       # then add your ANTHROPIC_API_KEY"
echo "  source .venv/bin/activate"
echo "  python main.py"

#!/usr/bin/env bash
# Download the word lists used by filter_words.py.
# Run from anywhere; files land next to this script.
set -euo pipefail
cd "$(dirname "$0")"

echo "Downloading full English word list (dwyl/english-words, ~370k words)..."
curl -fSL -o words_alpha.txt \
  "https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt"

echo "Downloading frequency-ranked common word list (google-10000-english)..."
curl -fSL -o google-10000.txt \
  "https://raw.githubusercontent.com/first20hours/google-10000-english/master/google-10000-english-no-swears.txt"

echo "Done:"
wc -l words_alpha.txt google-10000.txt

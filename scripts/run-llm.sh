#!/usr/bin/env bash
# Start the stage-1 guard LLM server (llama.cpp, CPU-only).
# 24 threads = physical cores on this 4-NUMA EPYC; 48 measured ~2x SLOWER.
set -euo pipefail
exec "$HOME/tools/llama.cpp/llama-b10076/llama-server" \
  -m "$HOME/models/pps/Qwen3-4B-Instruct-2507-Q4_K_M.gguf" \
  --host 127.0.0.1 --port 8641 -c 8192 --threads 24

#!/usr/bin/env bash
# Start the stage-1 guard LLM server (llama.cpp, CPU-only).
#
# Model: Qwen3-4B-Instruct-2507 (Q4_K_M). Qwen3.5-4B was evaluated on
# 2026-10-16 and rejected: no memory gain, ~2x slower per judgment on CPU,
# accuracy a wash (see README "Stage-1 model").
#
# Threads: 24 = physical cores on this 4-NUMA EPYC; 48 measured ~2x SLOWER.
#
# Memory: the weights are 2.5 GB. What made the server grow to ~14 GB RSS was
# the server-wide prompt cache, which defaults to 8 GiB in this build and fills
# up over a day of judging. 1 GiB holds a few full slots' worth of prompts,
# which is all that helps here (the shared system prompt + a handful of
# policies). The 8-bit KV cache and two 4096-token slots (pps sends at most
# PPS_MAX_TEXT_CHARS = 6000 chars plus the policy, ~2.5k tokens) keep the
# server near 4 GB. -c is the TOTAL context, split across the -np slots.
#
# Override the port for a side-by-side test: LLAMA_GUARD_PORT=18641 scripts/run-llm.sh
set -euo pipefail
exec "$HOME/tools/llama.cpp/llama-b10076/llama-server" \
  -m "$HOME/models/pps/Qwen3-4B-Instruct-2507-Q4_K_M.gguf" \
  --host 127.0.0.1 --port "${LLAMA_GUARD_PORT:-8641}" \
  -c 8192 -np 2 --threads 24 \
  -fa on -ctk q8_0 -ctv q8_0 \
  --cache-ram 1024

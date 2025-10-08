#!/usr/bin/env bash
set -euo pipefail

# Configurables
BENCH="./benchmark"              # ejecutable del benchmark
SAMPLER="./cache_sampler"        # sampler ya compilado
EVENT_TYPE="misses"              # "hits" o "misses"
FREQ=1000                    # frecuencia aproximada para sampler (Hz)
DURATION=10                      # duracion del sampler (No relevante, ya que se calcula una esperada)
RESULTS="results.csv"

# Parámetros del benchmark
N=3000      # tamaño matriz
REPS=5
WARMUP=1

if [ ! -x "$BENCH" ]; then
  echo "ERROR: benchmark executable $BENCH not found or not executable."
  exit 1
fi

if [ ! -x "$SAMPLER" ]; then
  echo "ERROR: sampler $SAMPLER not found or not executable."
  exit 1
fi

# CSV header
if [ ! -f "$RESULTS" ]; then
  echo "freq,event_type,N,reps,warmup,time_no_sampler,time_with_sampler,slowdown_percent" > "$RESULTS"
fi

# Helper para extraer el tiempo del benchmark
parse_time() {
  local file="$1"
  grep -Eo "time_s=[0-9]+\.[0-9]+" "$file" | sed 's/time_s=//'
}

# --- Baseline ---
OUTFILE="bench_no_sampler.out"
$BENCH $N $REPS $WARMUP > "$OUTFILE" 2>&1
time_no_sampler=$(parse_time "$OUTFILE")

# --- Benchmark con sampler ---
OUTFILE2="bench_with_sampler.out"
$BENCH $N $REPS $WARMUP > "$OUTFILE2" 2>&1 & bench_pid=$!
sleep 0.05

expected=$(awk "BEGIN{print $time_no_sampler * 1.5 + $DURATION}")
sudo $SAMPLER "$bench_pid" "$EVENT_TYPE" --freq="$FREQ" --duration="$expected" >/dev/null 2>&1 &
sampler_pid=$!

wait $bench_pid

if ps -p $sampler_pid > /dev/null 2>&1; then
  sudo kill "$sampler_pid" || true
fi

time_with_sampler=$(parse_time "$OUTFILE2")

# Calcular slowdown %
slowdown=$(awk -v t0="$time_no_sampler" -v t1="$time_with_sampler" \
              'BEGIN{ if (t0==0) print "nan"; else printf("%.6f", (t1 - t0) / t0 * 100.0) }')

# Guardar en el csv
echo "$FREQ,$EVENT_TYPE,$N,$REPS,$WARMUP,$time_no_sampler,$time_with_sampler,$slowdown" >> "$RESULTS"

echo "Results saved to $RESULTS"
echo "Slowdown % = $slowdown"


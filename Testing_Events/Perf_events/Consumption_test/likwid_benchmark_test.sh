#!/bin/bash

# Configuración
BENCH="store"              # Benchmark a ejecutar
WORKLOAD="S0:5GB:1"     # Tamaño del problema
OUT_NO_SAMPLER="nosampler.out"
OUT_WITH_SAMPLER="withsampler.out"
CSV_FILE="results2.csv"

# Ejecutables
SAMPLER="./cache_sampler"   # Ruta a tu sampler
DURATION=15                   # Duración de muestreo (segundos)
FREQ=1000                    # Frecuencia de muestreo (Hz)
EVENT_TYPE="misses"          # hits o misses

# Si no existe el CSV, crea encabezado
if [ ! -f "$CSV_FILE" ]; then
    echo "benchmark,workload,freq,event_type,time_no_sampler,time_with_sampler,slowdown_percent" > "$CSV_FILE"
fi

echo "Ejecutando benchmark $BENCH en workload $WORKLOAD..."

# 1) Ejecución sin sampler
/usr/bin/time -p likwid-bench -t $BENCH -w $WORKLOAD > $OUT_NO_SAMPLER 2>&1
TIME_NO_SAMPLER=$(grep "real" $OUT_NO_SAMPLER | awk '{print $2}')

# 2) Ejecución con sampler
# Lanzamos likwid-bench en background para obtener su PID
/usr/bin/time -p likwid-bench -t $BENCH -w $WORKLOAD > $OUT_WITH_SAMPLER 2>&1 &
BENCH_PID=$!
sleep 0.05

# Lanzamos el sampler apuntando al PID del benchmark
sudo $SAMPLER "$BENCH_PID" "$EVENT_TYPE" --freq="$FREQ" --duration="$DURATION" &
SAMPLER_PID=$!

# Esperamos a que likwid-bench termine
wait $BENCH_PID

# Sacamos tiempo con sampler
TIME_WITH_SAMPLER=$(grep "real" $OUT_WITH_SAMPLER | awk '{print $2}')

# Detener sampler si sigue corriendo
kill -9 $SAMPLER_PID 2>/dev/null

# 3) Calcular slowdown
SLOWDOWN=$(echo "scale=6; ($TIME_WITH_SAMPLER - $TIME_NO_SAMPLER) / $TIME_NO_SAMPLER * 100" | bc -l)

# 4) Guardar en CSV
echo "$BENCH,$WORKLOAD,$FREQ,$EVENT_TYPE,$TIME_NO_SAMPLER,$TIME_WITH_SAMPLER,$SLOWDOWN" >> $CSV_FILE

echo "✔ Benchmark $BENCH completado."
echo "Resultados guardados en $CSV_FILE"


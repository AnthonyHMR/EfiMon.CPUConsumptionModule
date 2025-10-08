# ========================
# eBPF Project Makefile
# ========================

# Directorios
SRC_DIR := src
INCLUDE_DIR := include
BUILD_DIR := build
SCRIPT_DIR := scripts
RESULTS_DIR := data/results
PLOTS_DIR := data/plots

# Archivos fuente
BPF_SRC := $(SRC_DIR)/prog.bpf.c
BPF_OBJ := $(BUILD_DIR)/prog.bpf.o
BPF_SKEL := $(INCLUDE_DIR)/prog.skel.h
VMLINUX := $(INCLUDE_DIR)/vmlinux.h
USER_SRC := $(SRC_DIR)/main.cpp
USER_BIN := $(BUILD_DIR)/sampler
BENCH_SRC := $(SRC_DIR)/benchmark.c
BENCH_BIN := $(BUILD_DIR)/benchmark
PLOT_SCRIPT := $(SCRIPT_DIR)/analyze_results.py
RESULT_FILE := $(RESULTS_DIR)/results.csv

# Compiladores
CLANG := clang
GPP := g++
GCC := gcc

# Flags de compilación
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
USER_CFLAGS := -O0 -g -Wall
BENCH_CFLAGS := -O0 -I/usr/include/openblas
BENCH_LIBS := -lopenblas -lm
USER_LIBS := -lbpf

# ========================
# Reglas principales
# ========================

all: | $(BUILD_DIR) $(INCLUDE_DIR) $(RESULTS_DIR) $(PLOTS_DIR) $(VMLINUX) $(BPF_OBJ) $(BPF_SKEL) $(USER_BIN) $(BENCH_BIN)
	@echo "Build completo."

$(BUILD_DIR) $(INCLUDE_DIR) $(RESULTS_DIR) $(PLOTS_DIR):
	@mkdir -p $@

# ========================
# Generar vmlinux.h
# ========================

$(VMLINUX):
	@echo "Generando vmlinux.h..."
	@mkdir -p $(INCLUDE_DIR)
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# ========================
# Compilar eBPF program
# ========================

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	@echo "Compilando programa eBPF..."
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# ========================
# Generar skeleton
# ========================

$(BPF_SKEL): $(BPF_OBJ)
	@echo "Generando skeleton..."
	bpftool gen skeleton $< > $@

# ========================
# Compilar programa de usuario (sampler)
# ========================

$(USER_BIN): $(USER_SRC) $(BPF_SKEL)
	@echo "Compilando programa en espacio de usuario..."
	$(GPP) $(USER_CFLAGS) $< -I$(INCLUDE_DIR) -o $@ $(USER_LIBS)

# ========================
# Compilar benchmark
# ========================

$(BENCH_BIN): $(BENCH_SRC)
	@echo "Compilando benchmark..."
	$(GCC) $(BENCH_CFLAGS) $< -o $@ $(BENCH_LIBS)

# ========================
# Ejecutar programa
# ========================

run:
ifndef PID
	$(error Debes pasar el PID del proceso a monitorear. Ejemplo: make run PID=1234 F=1000 D=10)
endif
ifndef F
	$(error Debes pasar la frecuencia de muestreo. Ejemplo: make run PID=1234 F=1000 D=10)
endif
ifndef D
	$(error Debes pasar la duración. Ejemplo: make run PID=1234 F=1000 D=10)
endif
	@echo "Ejecutando programa (PID=$(PID))..."
	sudo $(USER_BIN) $(PID) $(F) $(D)

# ========================
# Ejecutar script de pruebas
# ========================

test:
	@echo "Ejecutando script de testing..."
	chmod +x $(SCRIPT_DIR)/run_tests.sh
	$(SCRIPT_DIR)/run_tests.sh
	@echo "Benchmark completado, resultados guardados en $(RESULT_FILE)"

# ========================
# Generar gráficas de resultados
# ========================

plot:
	@echo "Generando gráficas con $(PLOT_SCRIPT)..."
	python3 $(PLOT_SCRIPT)
	@echo "Gráficas generadas en $(PLOTS_DIR)"

# ========================
# Limpieza
# ========================

clean:
	@echo "Limpiando archivos generados..."
	rm -f $(BPF_OBJ) $(USER_BIN) $(BENCH_BIN) $(BPF_SKEL)
	@echo "Limpieza completa."

.PHONY: all run test plot clean


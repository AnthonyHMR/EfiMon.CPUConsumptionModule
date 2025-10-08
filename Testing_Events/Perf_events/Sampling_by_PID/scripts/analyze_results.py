import pandas as pd
import matplotlib.pyplot as plt

# Cargar CSV
df = pd.read_csv("./data/results/results.csv")

# Calcular ralentización como ratio (nuevo / baseline)
df["slowdown_ratio"] = df["time_with_sampler"] / df["time_no_sampler"]

# Agrupar por frecuencia (opcional si tienes varias corridas por freq)
df_mean = df.groupby("freq", as_index=False)["slowdown_ratio"].mean()

# Graficar
plt.figure(figsize=(8,5))
plt.plot(df_mean["freq"], df_mean["slowdown_ratio"], marker="o", linestyle="-", color="steelblue")

plt.xlabel("Frecuencia de muestreo")
plt.ylabel("Ralentización (TiempoMedido / TiempoSinMedición)")
plt.title("Impacto de la frecuencia de muestreo en el rendimiento")
plt.grid(True)

# Guardar y mostrar
plt.savefig("./data/plots/slowdown_vs_freq.png", dpi=300)
plt.show()


import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# 1. Charger le dataset
df = pd.read_csv("dataset/csv/sc1_rr_balia.csv")

# 2. Afficher un rapide aperçu textuel
print("=== Aperçu des types et des valeurs manquantes ===")
print(df.info())
print("\n=== Statistiques descriptives (numériques) ===")
print(df.describe().T)

# 3. Figure 1 : Barres horizontales du nombre de valeurs manquantes
missing = df.isnull().sum()
plt.figure(figsize=(10, 8))
missing.plot(kind="barh", color="steelblue")
plt.title("Valeurs manquantes par variable")
plt.xlabel("Nombre de valeurs manquantes")
plt.ylabel("Variables")
plt.tight_layout()
plt.savefig("missing_values.png", dpi=300)
plt.show()

# 4. Figure 2 : Heatmap de la corrélation (sur variables numériques)
num = df.select_dtypes(include="number")
corr = num.corr()
plt.figure(figsize=(12, 10))
sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", cbar_kws={"shrink": .8})
plt.title("Matrice de corrélation des variables numériques")
plt.tight_layout()
plt.savefig("correlation_matrix.png", dpi=300)
plt.show()

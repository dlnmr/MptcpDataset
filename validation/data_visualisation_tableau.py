import pandas as pd

# Charger le fichier CSV
df = pd.read_csv('dataset/csv/sc1_rr_balia.csv')
# Récupérer la première ligne du DataFrame (index 0)
ligne = df.iloc[0].tolist()
# Liste des colonnes
columns = [
    "curr_Pid", "curr_CWND", "curr_sRTT", "curr_Th", "curr_Ds",
    "curr_Te", "curr_Gp", "curr_Fs", "curr_Bo",
    "fast_Pid", "fast_CWND", "fast_sRTT", "fast_Th", "fast_Ds",
    "fast_Te", "fast_Gp", "fast_Fs", "fast_Bo",
    "glob_Pid", "glob_CWND", "glob_sRTT", "glob_Th", "glob_Ds",
    "Timestamp", "Label"
]

# Compter le nombre de lignes (le premier élément de 'shape' correspond au nombre de lignes)
nombre_de_lignes = df.shape[0]

# Créer une liste vide pour stocker les informations
data = []
# Remplir la liste avec les informations demandées
for i, col in enumerate(columns):
    row = {
        "Index": i,
        "Nom d'entête": col,
        "Values Paramètres": ligne[i],
        "Nombre de lignes": nombre_de_lignes,
        "Type de variable": "Numeric" if pd.api.types.is_numeric_dtype(ligne[i]) else "Text"
    }
    data.append(row)

# Convertir la liste en DataFrame
result_df = pd.DataFrame(data)


# Enregistrer le DataFrame dans un fichier CSV
result_df.to_csv('resultat.txt', index=False)  # 'index=False' pour ne pas inclure la colonne d'index

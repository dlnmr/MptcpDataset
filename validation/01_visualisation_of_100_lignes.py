import pandas as pd

# 1) Définissez vos noms de colonnes (25 noms)
col_names = [
    "curr_Pid", "curr_CWND", "curr_sRTT", "curr_Th", "curr_Ds",
    "curr_Te", "curr_Gp", "curr_Fs", "curr_Bo",
    "fast_Pid", "fast_CWND", "fast_sRTT", "fast_Th", "fast_Ds",
    "fast_Te", "fast_Gp", "fast_Fs", "fast_Bo",
    "glob_Pid", "glob_CWND", "glob_sRTT", "glob_Th", "glob_Ds",
    "Timestamp", "Label"
]

# 2) Chargez le DataFrame en assignant ces noms
df = pd.read_csv("dataset/csv/sc1_rr_balia.csv", header=None, names=col_names)

# 3) Ajustez les options d’affichage pour ne plus tronquer les colonnes
pd.set_option("display.max_columns", None)      # Montre toutes les colonnes
pd.set_option("display.width", 1000)             # Largeur maximale de la console
pd.set_option("display.max_colwidth", None)     # Ne tronque pas le contenu des cellules

# 4) Affichez, par exemple, les 5 premières lignes en une seule ligne chacune
print(df.head(100).to_string(index=False))

import pandas as pd
import matplotlib.pyplot as plt
import os

# 📁 Liste des fichiers
files = [
    "dataset/csv/sc2_rr_balia.csv",
    "dataset/csv/sc2_blest_balia.csv",
    "dataset/csv/sc2_ecf_balia.csv",
    "dataset/csv/sc3_rr_balia.csv",
    "dataset/csv/sc3_blest_balia.csv",
    "dataset/csv/sc3_ecf_balia.csv",
    "dataset/csv/sc11_rr_balia.csv",
    "dataset/csv/sc11_blest_balia.csv",
    "dataset/csv/sc11_ecf_balia.csv"
]

# 🏷️ Noms des colonnes
column_names = [
    "curr_Pid", "curr_CWND", "curr_sRTT", "curr_Th", "curr_Ds",
    "curr_Te", "curr_Gp", "curr_Fs", "curr_Bo",
    "fast_Pid", "fast_CWND", "fast_sRTT", "fast_Th", "fast_Ds",
    "fast_Te", "fast_Gp", "fast_Fs", "fast_Bo",
    "glob_Pid", "glob_CWND", "glob_sRTT", "glob_Th", "glob_Ds",
    "Timestamp", "Label"
]

# 🎨 Couleurs fixes
colors = {0: "royalblue", 1: "lightskyblue"}
labels_letters = list("abcdefghi")

# 📊 Figure combinée
fig, axs = plt.subplots(3, 3, figsize=(14, 14))
axs = axs.flatten()

for i, path in enumerate(files):
    df = pd.read_csv(path, header=None, names=column_names)
    label_counts = df["Label"].value_counts().to_dict()

    # Forcer les valeurs dans l'ordre 0 puis 1, même si une valeur est absente
    sizes = [label_counts.get(0, 0), label_counts.get(1, 0)]
    colors_ordered = [colors[0], colors[1]]

    axs[i].pie(
        sizes,
        #labels=[f"Label 0", f"Label 1"],
        autopct='%1.1f%%',
        colors=colors_ordered,
        startangle=90,
        textprops={'fontsize': 20}
    )
    #title = os.path.basename(path).replace(".csv", "")
    #axs[i].set_title(f"({labels_letters[i]}) {title}", fontsize=10)
    axs[i].set_title(f"({labels_letters[i]})", fontsize=20)

# ✅ Légende uniforme
fig.legend(["0", "1"], title='labels',loc='lower center', ncol=2, fontsize=20)

plt.tight_layout(rect=[0, 0.05, 1, 1])
plt.savefig("diversity_label_fin.png", dpi=300)
plt.show()

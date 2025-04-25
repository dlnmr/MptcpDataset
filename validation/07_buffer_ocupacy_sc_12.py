import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# 📁 Fichiers sélectionnés
files = [
    "dataset/csv/sc12_rr_balia.csv",
    "dataset/csv/sc12_blest_balia_3.csv",
    "dataset/csv/sc12_ecf_balia.csv",
    "dataset/csv/sc12_rr_olia.csv",
    "dataset/csv/sc12_blest_olia_3.csv",
    "dataset/csv/sc12_ecf_olia.csv",
    "dataset/csv/sc12_rr_lia.csv",
    "dataset/csv/sc12_blest_lia_3.csv",
    "dataset/csv/sc12_ecf_lia.csv"
]

# 🏷️ Noms des colonnes
column_names = [
    "curr_Pid", "curr_CWND", "curr_sRTT", "curr_Th", "curr_Ds",
    "curr_Te", "curr_Gp", "curr_Fs", "curr_Bo",
    "fast_Pid", "fast_CWND", "fast_sRTT", "fast_Th", "fast_Ds",
    "fast_Te", "fast_Gp", "fast_Fs", "fast_Bo",
    "glob_Pid", "glob_CWND", "glob_sRTT", "glob_Fs", "glob_Bo",
    "Timestamp", "Label"
]

# 🎨 Dictionnaires couleur et hatch
scheduler_colors = {
    "rr": "cornflowerblue",   # bleu clair
    "blest": "red",           # rouge
    "ecf": "gold"             # jaune
}

cc_hatch = {
    "balia": "++",  # diagonale
    "olia": "oo",   # croix
    "lia": "xx"     # ronds
}

# 📊 Lecture de tous les fichiers et création d'un seul DataFrame
dfs = []
for path in files:
    df = pd.read_csv(path, header=None, names=column_names)
    filename = os.path.basename(path).replace(".csv", "")
    parts = filename.split("_")
    scheduler = parts[1]
    cc_algo = parts[2]
    df["Scheduler"] = scheduler
    df["CC"] = cc_algo
    df["Source"] = filename
    dfs.append(df)

all_data = pd.concat(dfs)

# 🖼️ Préparation de la figure
plt.figure(figsize=(18, 8))
ax = plt.gca()

# 🔥 Tracer manuellement chaque groupe
positions = []
labels = []
current_pos = 1

for scheduler in ["rr", "blest", "ecf"]:
    for cc in ["olia", "lia", "balia"]:
        subset = all_data[(all_data["Scheduler"] == scheduler) & (all_data["CC"] == cc)]
        if not subset.empty:
            bplot = plt.boxplot(
                subset["glob_Bo"],
                positions=[current_pos],
                widths=0.5,
                patch_artist=True,
                boxprops=dict(
                    facecolor=scheduler_colors[scheduler],
                    hatch=cc_hatch[cc],
                    edgecolor="black"
                ),
                medianprops=dict(color="black")
            )
            labels.append(f"{scheduler.upper()}-{cc.upper()}")
            positions.append(current_pos)
            current_pos += 1

# ✏️ Mise en forme
#plt.xticks(positions, labels, rotation=45, ha='right')
plt.xticks(positions, labels)
plt.ylabel("Occupation du buffer (octets) de la session globale (curr_Bo) ")
plt.title("(a)", fontsize=20)
plt.grid(axis='y', linestyle='--', alpha=0.7)

# 🗺️ Construction manuelle d'une légende
import matplotlib.patches as mpatches

legend_elements = [
    mpatches.Patch(facecolor='cornflowerblue', label='RR', edgecolor='black'),
    mpatches.Patch(facecolor='red', label='BLEST', edgecolor='black'),
    mpatches.Patch(facecolor='gold', label='ECF', edgecolor='black'),
    mpatches.Patch(facecolor='white', edgecolor='black', hatch='++', label='Balia'),
    mpatches.Patch(facecolor='white', edgecolor='black', hatch='oo', label='Olia'),
    mpatches.Patch(facecolor='white', edgecolor='black', hatch='xx', label='Lia'),
]

plt.legend(handles=legend_elements, title="Equi & CC", loc='upper left', fontsize=20)
plt.tight_layout()

# 📥 Sauvegarde
plt.savefig("buffer_occupation_sc_12.png", dpi=300)

# 📈 Affichage
plt.show()

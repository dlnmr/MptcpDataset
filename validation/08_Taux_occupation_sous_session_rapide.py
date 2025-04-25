import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os

# 📂 Liste originale des fichiers
files = [
    "dataset/csv/sc14_blest_balia.csv",
    "dataset/csv/sc14_blest_lia.csv",
    "dataset/csv/sc14_blest_olia.csv",
    "dataset/csv/sc14_ecf_balia.csv",
    "dataset/csv/sc14_ecf_lia.csv",
    "dataset/csv/sc14_ecf_olia.csv",
    "dataset/csv/sc14_rr_balia.csv",
    "dataset/csv/sc14_rr_lia.csv",
    "dataset/csv/sc14_rr_olia.csv",
]

# 📑 Colonnes
column_names = [
    "curr_Pid", "curr_CWND", "curr_sRTT", "curr_Th", "curr_Ds",
    "curr_Te", "curr_Gp", "curr_Fs", "curr_Bo",
    "fast_Pid", "fast_CWND", "fast_sRTT", "fast_Th", "fast_Ds",
    "fast_Te", "fast_Gp", "fast_Fs", "fast_Bo",
    "glob_Pid", "glob_CWND", "glob_sRTT", "glob_Fs", "glob_Bo",
    "Timestamp", "Label"
]

# 🎨 Couleurs par ordonnanceur
scheduler_colors = {
    "rr": "cornflowerblue",   # bleu clair
    "blest": "red",           # rouge
    "ecf": "gold"             # jaune
}

# 🎨 Motifs par congestion control
cc_hatch = {
    "balia": "++",  # diagonale croisée
    "olia": "oo",   # cercles
    "lia": "xx"     # croix
}

# 📊 Stocker résultats
occupation_rates = []
labels = []
bar_colors = []
bar_hatches = []

for path in files:
    df = pd.read_csv(path, header=None, names=column_names)

    # Filtrer uniquement les segments envoyés
    sent_segments = df[df["Label"] == 1]
    total_sent = len(sent_segments)
    fast_path_sent = len(sent_segments[sent_segments["curr_Pid"] == sent_segments["glob_Pid"]])

    occupation_rate = (fast_path_sent / total_sent) * 100 if total_sent > 0 else 0

    filename = os.path.basename(path).replace(".csv", "")
    labels.append(filename)
    occupation_rates.append(occupation_rate)

    # 🎯 Détecter scheduler et CC dans le nom de fichier
    if "_blest_" in filename:
        bar_colors.append(scheduler_colors["blest"])
    elif "_ecf_" in filename:
        bar_colors.append(scheduler_colors["ecf"])
    elif "_rr_" in filename:
        bar_colors.append(scheduler_colors["rr"])
    else:
        bar_colors.append("grey")  # Par défaut

    if "balia" in filename:
        bar_hatches.append(cc_hatch["balia"])
    elif "olia" in filename:
        bar_hatches.append(cc_hatch["olia"])
    elif "lia" in filename:
        bar_hatches.append(cc_hatch["lia"])
    else:
        bar_hatches.append("")

# 📈 Création de la figure
fig, ax = plt.subplots(figsize=(14, 8))

bars = []
for i in range(len(labels)):
    bar = ax.barh(
        labels[i],
        occupation_rates[i],
        color=bar_colors[i],
        hatch=bar_hatches[i],
        edgecolor='black'
    )
    bars.append(bar)

# 📜 Légende personnalisée
legend_elements = [
    mpatches.Patch(facecolor='cornflowerblue', label='RR', edgecolor='black'),
    mpatches.Patch(facecolor='red', label='BLEST', edgecolor='black'),
    mpatches.Patch(facecolor='gold', label='ECF', edgecolor='black'),
    mpatches.Patch(facecolor='white', edgecolor='black', hatch='++', label='Balia'),
    mpatches.Patch(facecolor='white', edgecolor='black', hatch='oo', label='Olia'),
    mpatches.Patch(facecolor='white', edgecolor='black', hatch='xx', label='Lia'),
]

ax.legend(handles=legend_elements, title="Equi & CC", loc='lower left', fontsize=20)

# ✏️ Ajout des pourcentages sur les barres
for bar in bars:
    width = bar[0].get_width()
    ax.annotate(f'{width:.1f}%', xy=(width, bar[0].get_y() + bar[0].get_height()/2),
                xytext=(5, 0), textcoords="offset points", ha='left', va='center', fontsize=10)

ax.set_xlabel("Taux d'occupation de la sous-session rapide (%)", fontsize=20)
ax.set_ylabel("Scenarios", fontsize=20)
ax.set_title("(b)", fontsize=20)
plt.grid(axis='x')
plt.tight_layout()
plt.savefig("Taux_occupation_sc_14_Fin.png", dpi=300)
plt.show()

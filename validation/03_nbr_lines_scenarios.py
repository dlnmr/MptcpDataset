import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load your DataFrame
df = pd.read_csv("all_sc_v00.txt")
n = len(df)

# Choose your “highlight” color for the first 3 bars
first3_color = 'darkorange'

# Prepare a list of colors for the 9-bar groups (repeat as needed)
group_colors = plt.cm.tab20(np.linspace(0,1, (n-3)//9 + 1 ))

# Build the per-bar color list
colors = []
for i in range(n):
    if i < 3:
        colors.append(first3_color)
    else:
        # compute which 9-bar block (0-based) this bar is in:
        block = (i - 3) // 9
        colors.append(group_colors[block])

# Plot
plt.figure(figsize=(15,10), dpi=600)
plt.barh(df['fichiers'], df['nombre_de_lignes'], color=colors)

plt.title('Nombre de Lignes par Scenario (du scenario 1 à 15)', fontsize=16)
plt.xlabel('Nombre de Lignes', fontsize=12)
plt.ylabel('Scenarios', fontsize=12)

# Adjust ticks
x_ticks = np.linspace(0, df['nombre_de_lignes'].max(), num=20)
plt.xticks(x_ticks, fontsize=8)
plt.yticks(fontsize=4)

plt.tight_layout()
plt.savefig('graphe_1_fin.png', dpi=600)
plt.show()

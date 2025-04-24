import pandas as pd
import matplotlib.pyplot as plt

# Charger les donnees pour le premier graphique
data1 = {
    'Scenario': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    'Nombre_de_lignes': [1560971, 5470132, 5434728, 5517675, 5531226, 5565552, 
                         5590008, 5606887, 5655638, 5694858, 5899478, 5419984, 
                         5607687, 5655590, 5822857]
}
df1 = pd.DataFrame(data1)

# Couleurs pour le premier graphique
couleurs1 = [
    'red', 'lightgreen', 'lightblue', 'salmon', 'yellow', 'orange',
    'purple', 'cyan', 'magenta', 'gold', 'violet', 'coral', 
    'lime', 'turquoise', 'plum'
]

# Charger les donnees pour le deuxième graphique
data2 = {
    'Scenario': ['RR & LIA', 'RR & OLIA', 'RR & BALIA', 'BLEST & LIA', 
                 'BLEST & LIA', 'BLEST & LIA', 'ECF & LIA', 'ECF & LIA', 
                 'ECF & LIA'],
    'Nombre_de_lignes': [524869, 520820, 534756, 632350, 649736, 624642, 
                         660028, 642232, 680699]
}
df2 = pd.DataFrame(data2)

# Couleurs pour le deuxième graphique
couleurs2 = [
    'red', 'lightgreen', 'lightblue', 'salmon', 'yellow', 'orange',
    'purple', 'cyan', 'magenta', 'gold', 'violet', 'coral', 
    'lime', 'turquoise', 'plum'
]

# Creer une figure avec 2 sous-graphes côte à côte
fig, axs = plt.subplots(1, 2, figsize=(16, 8))

# Fonction pour afficher les valeurs en gras
def func(pct, allvalues):
    absolute = int(pct / 100. * sum(allvalues))
    return f'{absolute}'

# Premier diagramme circulaire
wedges1, texts1, autotexts1 = axs[0].pie(df1['Nombre_de_lignes'], labels=df1['Scenario'], 
                                         autopct='%1.1f%%', 
                                         startangle=90, 
                                         counterclock=False,
                                         pctdistance=0.85,
                                         colors=couleurs1)

# Changer la couleur et le style du texte pour le premier graphique
for autotext in autotexts1:
    autotext.set_color('darkblue')
    autotext.set_fontsize(18)
    autotext.set_weight('bold')

for text in texts1:
    text.set_fontsize(12)
    text.set_weight('bold')

axs[0].axis('equal')  # Pour que le cercle soit bien proportionné
axs[0].set_title('(a)', fontweight='bold', fontsize=20)

# Deuxième diagramme circulaire
wedges2, texts2, autotexts2 = axs[1].pie(df2['Nombre_de_lignes'], labels=df2['Scenario'], 
                                         autopct=lambda pct: func(pct, df2['Nombre_de_lignes']), 
                                         startangle=90, 
                                         counterclock=False,
                                         pctdistance=0.85,
                                         colors=couleurs2)

# Changer la couleur et le style du texte pour le deuxième graphique
for autotext in autotexts2:
    autotext.set_color('darkblue')
    autotext.set_fontsize(18)
    autotext.set_weight('bold')

for text in texts2:
    text.set_fontsize(12)
    text.set_weight('bold')

axs[1].axis('equal')  # Pour que le cercle soit bien proportionné
axs[1].set_title('(b)', fontweight='bold', fontsize=20)

# Afficher la figure
plt.tight_layout()
plt.savefig('combined_diagram_500.png', bbox_inches='tight', dpi=500)
plt.show()

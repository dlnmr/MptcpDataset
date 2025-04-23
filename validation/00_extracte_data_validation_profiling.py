import os, sys
import numpy as np
from ydata_profiling import ProfileReport
import pandas as pd
import json
path = "dataset/csv"
dirs = os.listdir( path )
fichiers=np.array([])
nombre_de_lignes=np.array([])
nombre_de_colones=np.array([])
nombre_de_Cellules_manquantes=np.array([])
types_de_variables=np.array([])
for file in dirs:
   if ".csv" in file :
       nameFile="dataset/csv/"+file
       fichiers=np.append(fichiers,file)
       # Chargez votre DataFrame
       df = pd.read_csv(nameFile)
       # 2. Create the profile
       profile = ProfileReport(df, title=nameFile+"_Report", minimal=True)
       jsonFiles = nameFile+".json"
       profile.to_file(jsonFiles)
       with open(jsonFiles, "r") as f:
           report = json.load(f)
       overview = report["table"]
       nombre_de_lignes=np.append(nombre_de_lignes,overview['n'])
       nombre_de_colones=np.append(nombre_de_colones,overview['n_var'])
       nombre_de_Cellules_manquantes=np.append(nombre_de_Cellules_manquantes,overview['n_cells_missing'])
       types_de_variables=np.append(types_de_variables,overview['types'])
dff = pd.DataFrame({
         "fichiers"                       : fichiers,
         "nombre_de_lignes"               : nombre_de_lignes,
	"nombre_de_colones"               : nombre_de_colones,
	"nombre_de_Cellules_manquantes"   : nombre_de_Cellules_manquantes,
	"types_de_variables"              : types_de_variables             
})
dff.to_csv('allSc.txt', index=False)

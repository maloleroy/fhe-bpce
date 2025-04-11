# Voir execsum.pdf pour plus d'informations sur le système de chiffrement en question ici
# Ce programme montre que, en connaissant les paramètres de la loi de bruit,
# on peut retrouver la clé secrète en quelques secondes en Python.

# Voir crack.pdf pour plus d'informations sur la méthode pour inverser le système

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from concurrent.futures import ThreadPoolExecutor

# Load data
df = pd.read_parquet('playground.parquet', engine='pyarrow')
ser = df['rwa'][::500]
n = len(ser)
print("Number of rows: ", n)

# Clé secrète
S = 5

# Imaginons que la données sont chiffrées k fois, en estimant que la moyenne de change pas beaucoup
k = 500

# Génération du bruit (uniforme)
e = np.random.randint(-10, 10, [k, n])

def compute_mean(row):
    return np.mean(row)

# Chiffrement
data = S * e + np.full((k, n), ser)

# Calcul de la moyenne 
with ThreadPoolExecutor() as executor:
    results = list(executor.map(compute_mean, data))
moy = np.mean(data, axis=1)

# Statistiques empiriques
moy_emp = np.mean(moy)
std_emp = np.std(moy, ddof=1)

max_emp = np.max(moy)
min_emp = np.min(moy)

print(f"Mean: {moy_emp}")
print(f"Standard deviation: {std_emp}")
print(f"Max: {max_emp}")
print(f"Min: {min_emp}")

# Estimation de la clé secrète par rapport des écarts-types
sigma = np.sqrt((20**2-1)/(12*n))
print(f"Real Secret Key: {S}")
print(f"Crack: {(std_emp) / sigma}")
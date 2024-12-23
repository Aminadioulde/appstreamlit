
import pandas as pd
import joblib
import streamlit as st
import numpy as np
import pefile  # Bibliothèque pour analyser les fichiers PE (exécutables Windows)
import os
import tempfile

def extract_features_from_exe(executable_path):
    """
    Extrait les 7 caractéristiques nécessaires à partir d'un fichier exécutable réel.
    Utilise la bibliothèque pefile pour extraire les informations pertinentes.
    """
    try:
        pe = pefile.PE(executable_path)
        
        # Caractéristiques attendues
        characteristics = [
            pe.OPTIONAL_HEADER.AddressOfEntryPoint,                # AddressOfEntryPoint
            pe.OPTIONAL_HEADER.DllCharacteristics,                # DllCharacteristics
            pe.OPTIONAL_HEADER.MajorImageVersion,                 # MajorImageVersion
            pe.OPTIONAL_HEADER.MajorLinkerVersion,                # MajorLinkerVersion
            pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,       # MajorOperatingSystemVersion
            len(pe.sections),                                     # NumberOfSections
            pe.OPTIONAL_HEADER.SizeOfStackReserve                 # SizeOfStackReserve
        ]
        return characteristics
    except AttributeError as e:
        st.error(f"Erreur lors de l'accès à un attribut : {e}")
        return None
    except Exception as e:
        st.error(f"Erreur lors de l'extraction des caractéristiques : {e}")
        return None


# Chargement du modèle pré-entraîné
MODEL_PATH = "model.pkl"
try:
    model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    st.error(f"Le modèle {MODEL_PATH} est introuvable. Veuillez le charger correctement.")
    st.stop()

# Chargement de la base de données pour les noms de caractéristiques
#DATASET_PATH = "../DatasetmalwareExtrait.csv"
#try:
    #df = pd.read_csv(DATASET_PATH)
    #feature_names = df.columns[:-1]  # Supposons que la dernière colonne est la cible
#except FileNotFoundError:
    #st.error(f"Le fichier {DATASET_PATH} est introuvable. Veuillez vérifier le chemin.")
    #st.stop()
# Remplacez feature_names par les noms exacts des colonnes attendues
feature_names = [
    "AddressOfEntryPoint",
    "DllCharacteristics",
    "MajorImageVersion",
    "MajorLinkerVersion",
    "MajorOperatingSystemVersion",
    "NumberOfSections",
    "SizeOfStackReserve"
]

# Streamlit App
st.title("Détection de Malware")

# Interface pour prédire un exécutable
st.header("Prédiction d'un exécutable")
uploaded_file = st.file_uploader("Téléversez un exécutable", type=["exe"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(uploaded_file.read())
        executable_path = tmp_file.name
    
    st.write("Exécutable téléversé :", uploaded_file.name)
    
    # Extraction des caractéristiques
    #features = extract_features_from_exe(executable_path)
    #if features is not None:
        #features_dict = {name: value for name, value in zip(feature_names, features)}
        #st.write("Caractéristiques extraites :", features_dict)

        # Prédiction
        #prediction = model.predict([features])[0]
        #prediction_proba = model.predict_proba([features])[0]

        # Résultat
        #if prediction == 1:
            #st.error("C'est un malware !")
        #else:
            #st.success("C'est un fichier légitime.")

        #st.write("Probabilités :", {"Légitime": prediction_proba[0], "Malware": prediction_proba[1]})
    #else:
        #st.error("Impossible d'extraire les caractéristiques du fichier téléversé.")

    # Nettoyage du fichier temporaire
    #os.remove(executable_path)
    # Extraction des caractéristiques
    features = extract_features_from_exe(executable_path)
    if features is not None:
    # Création du dictionnaire avec les noms et les valeurs
        features_dict = {name: value for name, value in zip(feature_names, features)}
        st.write("Caractéristiques extraites :", features_dict)

    # Prédiction
        prediction = model.predict([features])[0]
        prediction_proba = model.predict_proba([features])[0]

    # Résultat
        if prediction == 1:
            st.error("C'est un malware !")
        else:
            st.success("C'est un fichier légitime.")

        st.write("Probabilités :", {"Légitime": prediction_proba[0], "Malware": prediction_proba[1]})
    else:
        st.error("Impossible d'extraire les caractéristiques du fichier téléversé.")
 # Nettoyage du fichier temporaire
   # os.remove(executable_path)


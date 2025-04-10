import streamlit as st
from datetime import datetime
import re
import joblib
import nltk
import ssl
from cryptography.fernet import Fernet


# --- Sécurisation et robustesse du téléchargement NLTK ---
def ensure_nltk_data():
    try:
        _create_unverified_https_context = ssl._create_unverified_context
    except AttributeError:
        pass
    else:
        ssl._create_default_https_context = _create_unverified_https_context

    resources = {
        "punkt": "tokenizers/punkt",
        "stopwords": "corpora/stopwords",
        "wordnet": "corpora/wordnet"
    }

    for key, path in resources.items():
        try:
            nltk.data.find(path)
        except LookupError:
            nltk.download(key)

# Appel immédiat pour garantir la disponibilité des ressources
ensure_nltk_data()


# --- Personnalisation CSS pour thème cybersécurité / IA ---
st.markdown(
    """
    <style>
    body {
        background-color: #121212;
    }
    .stApp {
        background-image: url("https://images.unsplash.com/photo-1518770660439-4636190af475?ixlib=rb-1.2.1&auto=format&fit=crop&w=1350&q=80");
        background-size: cover;
        background-attachment: fixed;
        filter: brightness(0.85) contrast(0.8);
    }
    .title {
        font-size: 3rem;
        color: #bb86fc;
        text-align: center;
        font-weight: bold;
        text-shadow: 2px 2px #000;
    }
    .stButton button {
        background-color: #bb86fc;
        color: #121212;
        border-radius: 10px;
        border: none;
        padding: 10px 20px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --- Chargement du modèle et du vectoriseur ---
model = joblib.load("model_secure.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")


# --- Gestion des accès ---
USERS = {
    "data_scientist": "Olivier",
    "analyst": "Yvan"
}

fernet_key = "yM3-e-98fkF8aL8VT5mDLttqxtAfa7zwI_gndx0kGP8="
fernet = Fernet(fernet_key.encode())


# --- Nettoyage du texte ---
def clean_text(text):
    text = text.lower()
    text = re.sub(r"[^a-zA-Z\s]", "", text)
    tokens = nltk.word_tokenize(text)
    tokens = [t for t in tokens if t not in nltk.corpus.stopwords.words("english")]
    return " ".join(tokens)


# --- Logging des actions ---
def log_access(role, action):
    with open("log_access.txt", "a") as f:
        f.write(f"[{datetime.now()}] {role.upper()} - {action}\n")


# --- Initialisation de la session Streamlit ---
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_role" not in st.session_state:
    st.session_state.user_role = None


# --- Authentification dans la sidebar ---
with st.sidebar:
    st.header("Authentification")
    role = st.selectbox("Sélectionnez votre rôle", list(USERS.keys()))
    token = st.text_input("Entrez votre token d'accès", type="password")
    if st.button("Se connecter"):
        if token == USERS.get(role):
            st.success(f"Bienvenue, {role}")
            st.session_state.authenticated = True
            st.session_state.user_role = role
            log_access(role, "Connexion réussie")
        else:
            st.error("Token invalide.")
            st.session_state.authenticated = False


# --- Interface principale ---
if st.session_state.authenticated:
    st.markdown("<div class='title'>🔐 SecureNLP Interface</div>", unsafe_allow_html=True)
    st.subheader("Designed by Olivier Hell and Yvan Kappu")

    commentaire = st.text_area("✏️ Entrez votre commentaire à analyser")
    if st.button("Analyser"):
        if commentaire.strip() == "":
            st.warning("Le champ ne peut pas être vide.")
        else:
            try:
                log_access(st.session_state.user_role, "Demande de prédiction")
                cleaned = clean_text(commentaire)
                X = vectorizer.transform([cleaned])
                pred = model.predict(X)[0]
                label = "NEGATIVE" if pred else "POSITIVE"
                encrypted = fernet.encrypt(label.encode()).decode()

                if st.session_state.user_role == "analyst":
                    st.write("🔐 Résultat chiffré :")
                    st.code(encrypted)
                else:
                    st.write(f"✅ Prédiction : **{label}**")
                    st.write("🔐 Résultat chiffré :", encrypted)
            except Exception as e:
                st.error(f"Erreur lors de la prédiction : {str(e)}")
else:
    st.info("Veuillez vous connecter via le menu latéral pour accéder à l'application.")



import ollama
import json
import os
import glob
import time
import sqlite3
import re
from typing import List, Dict, Any
from tqdm import tqdm

from langchain.schema import Document
from langchain_ollama import OllamaEmbeddings

# Amélioration 1: Structure pour stocker le contexte récemment utilisé
class ConversationContext:
    def __init__(self, max_context_items=5):
        self.recent_cve_ids = []  # Liste des CVE IDs récemment consultés
        self.recent_contexts = {}  # Dictionnaire CVE ID -> contexte
        self.max_context_items = max_context_items
    
    def add_context(self, cve_id, context):
        if cve_id:
            # Si le CVE existe déjà, le déplacer en tête de liste
            if cve_id in self.recent_cve_ids:
                self.recent_cve_ids.remove(cve_id)
            
            # Ajouter le CVE à la liste
            self.recent_cve_ids.insert(0, cve_id)
            self.recent_contexts[cve_id] = context
            
            # Limiter la taille
            if len(self.recent_cve_ids) > self.max_context_items:
                oldest = self.recent_cve_ids.pop()
                if oldest in self.recent_contexts:
                    del self.recent_contexts[oldest]
    
    def get_recent_context(self, cve_id=None):
        # Si un CVE spécifique est demandé
        if cve_id and cve_id in self.recent_contexts:
            return self.recent_contexts[cve_id]
        
        # Si on veut le contexte le plus récent
        if self.recent_cve_ids:
            most_recent = self.recent_cve_ids[0]
            return self.recent_contexts.get(most_recent, "")
        
        return ""

# 1. Création de la base de données SQLite
def setup_sqlite_db(db_path: str = "cve_database.db"):
    """Crée ou se connecte à la base de données SQLite et configure les tables nécessaires"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Table principale pour les CVE
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve (
        id INTEGER PRIMARY KEY,
        cve_id TEXT UNIQUE,
        description TEXT,
        date_published TEXT,
        year TEXT,
        source TEXT
    )
    ''')
    
    # Table pour les produits (relation many-to-many)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE
    )
    ''')
    
    # Table de jointure pour CVE-Products
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve_products (
        cve_id INTEGER,
        product_id INTEGER,
        PRIMARY KEY (cve_id, product_id),
        FOREIGN KEY (cve_id) REFERENCES cve(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
    )
    ''')
    
    # Table pour les références (rename "references" to "cve_references" to avoid SQL keyword conflict)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS cve_references (
        id INTEGER PRIMARY KEY,
        cve_id INTEGER,
        url TEXT,
        FOREIGN KEY (cve_id) REFERENCES cve(id)
    )
    ''')
    
    # Table pour stocker les embeddings des descriptions (optionnelle)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS embeddings (
        cve_id INTEGER PRIMARY KEY,
        embedding BLOB,
        FOREIGN KEY (cve_id) REFERENCES cve(id)
    )
    ''')
    
    # Création des index pour améliorer les performances de recherche
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_id ON cve(cve_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_year ON cve(year)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_products ON products(name)')
    
    conn.commit()
    return conn

# 2. Chargement des données CVE depuis les fichiers JSON vers SQLite
def load_cve_data_to_sqlite(directory_path: str, conn):
    """Charge les données CVE des fichiers JSON vers la base SQLite"""
    cursor = conn.cursor()
    json_files = glob.glob(os.path.join(directory_path, "cve_*.json"))
    
    total_cves = 0
    
    for file_path in tqdm(json_files, desc="Traitement des fichiers JSON"):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                cve_data = json.load(file)
                
                # Extraction de l'année depuis le nom du fichier
                year = os.path.basename(file_path).split('_')[1].split('.')[0]
                
                # Traitement par lots pour améliorer les performances
                for cve_item in tqdm(cve_data, desc=f"Traitement des CVE de {year}", leave=False):
                    cve_id = cve_item.get('cve_id', '')
                    description = cve_item.get('description', '')
                    date_published = cve_item.get('date_published', '')
                    source = os.path.basename(file_path)
                    products = cve_item.get('products', [])
                    references = cve_item.get('references', [])
                    
                    # Insertion du CVE principal
                    try:
                        cursor.execute(
                            'INSERT OR IGNORE INTO cve (cve_id, description, date_published, year, source) VALUES (?, ?, ?, ?, ?)',
                            (cve_id, description, date_published, year, source)
                        )
                        
                        # Récupérer l'ID du CVE inséré
                        cursor.execute('SELECT id FROM cve WHERE cve_id = ?', (cve_id,))
                        cve_db_id = cursor.fetchone()[0]
                        
                        # Insertion des produits et de leurs relations
                        for product in products:
                            cursor.execute('INSERT OR IGNORE INTO products (name) VALUES (?)', (product,))
                            cursor.execute('SELECT id FROM products WHERE name = ?', (product,))
                            product_id = cursor.fetchone()[0]
                            
                            cursor.execute('INSERT OR IGNORE INTO cve_products (cve_id, product_id) VALUES (?, ?)',
                                        (cve_db_id, product_id))
                        
                        # Insertion des références
                        for ref in references:
                            cursor.execute('INSERT OR IGNORE INTO cve_references (cve_id, url) VALUES (?, ?)',
                                        (cve_db_id, ref))
                        
                        total_cves += 1
                        
                        # Commit par lots pour éviter une transaction trop grande
                        if total_cves % 1000 == 0:
                            conn.commit()
                            
                    except sqlite3.IntegrityError:
                        # Ignorer les doublons
                        pass
                
        except Exception as e:
            print(f"Erreur lors du chargement du fichier {file_path}: {e}")
    
    conn.commit()
    print(f"Nombre total de CVE chargés: {total_cves}")

# 3. Fonction pour récupérer les données CVE de la base SQLite
def get_cve_by_id(conn, cve_id: str) -> List[Document]:
    """Récupère toutes les informations sur un CVE spécifique par son ID"""
    cursor = conn.cursor()
    
    # Nettoyage de l'ID CVE
    cve_id = cve_id.strip().upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    
    # Récupérer les informations de base du CVE
    cursor.execute('''
    SELECT c.id, c.cve_id, c.description, c.date_published, c.year, c.source
    FROM cve c
    WHERE c.cve_id = ?
    ''', (cve_id,))
    
    cve_results = cursor.fetchall()
    documents = []
    
    for cve_result in cve_results:
        cve_db_id, cve_id, description, date_published, year, source = cve_result
        
        # Récupérer les produits associés
        cursor.execute('''
        SELECT p.name
        FROM products p
        JOIN cve_products cp ON p.id = cp.product_id
        WHERE cp.cve_id = ?
        ''', (cve_db_id,))
        
        products = [row[0] for row in cursor.fetchall()]
        
        # Récupérer les références
        cursor.execute('''
        SELECT url
        FROM cve_references
        WHERE cve_id = ?
        ''', (cve_db_id,))
        
        references = [row[0] for row in cursor.fetchall()]
        
        # Formater le contenu
        cve_content = f"""
CVE ID: {cve_id}
Products: {', '.join(products)}
Description: {description}
Date Published: {date_published}
References:
{chr(10).join(['- ' + ref for ref in references])}
"""
        
        doc = Document(
            page_content=cve_content.strip(),
            metadata={
                "cve_id": cve_id,
                "source": source,
                "year": year,
                "products": products
            }
        )
        documents.append(doc)
    
    return documents

# 4. Fonction pour rechercher des CVE par mot-clé
def search_cve_by_keyword(conn, keyword: str, limit: int = 5) -> List[Document]:
    """Recherche des CVE contenant un mot-clé dans la description ou les produits"""
    cursor = conn.cursor()
    
    # Préparation du mot-clé pour la recherche LIKE
    search_term = f"%{keyword}%"
    
    # Recherche par description
    cursor.execute('''
    SELECT c.id, c.cve_id, c.description, c.date_published, c.year, c.source
    FROM cve c
    WHERE c.description LIKE ?
    LIMIT ?
    ''', (search_term, limit))
    
    cve_results = cursor.fetchall()
    documents = []
    
    # Recherche par produit
    cursor.execute('''
    SELECT DISTINCT c.id, c.cve_id, c.description, c.date_published, c.year, c.source
    FROM cve c
    JOIN cve_products cp ON c.id = cp.cve_id
    JOIN products p ON cp.product_id = p.id
    WHERE p.name LIKE ?
    LIMIT ?
    ''', (search_term, limit))
    
    # Combiner les résultats
    cve_results.extend(cursor.fetchall())
    
    # Dédupliquer les résultats par ID
    seen_ids = set()
    unique_results = []
    
    for result in cve_results:
        if result[0] not in seen_ids:
            seen_ids.add(result[0])
            unique_results.append(result)
    
    # Limiter au nombre demandé
    unique_results = unique_results[:limit]
    
    # Formater les résultats
    for cve_result in unique_results:
        cve_db_id, cve_id, description, date_published, year, source = cve_result
        
        # Récupérer les produits associés
        cursor.execute('''
        SELECT p.name
        FROM products p
        JOIN cve_products cp ON p.id = cp.product_id
        WHERE cp.cve_id = ?
        ''', (cve_db_id,))
        
        products = [row[0] for row in cursor.fetchall()]
        
        # Récupérer les références
        cursor.execute('''
        SELECT url
        FROM cve_references
        WHERE cve_id = ?
        ''', (cve_db_id,))
        
        references = [row[0] for row in cursor.fetchall()]
        
        # Formater le contenu
        cve_content = f"""
CVE ID: {cve_id}
Products: {', '.join(products)}
Description: {description}
Date Published: {date_published}
References:
{chr(10).join(['- ' + ref for ref in references])}
"""
        
        doc = Document(
            page_content=cve_content.strip(),
            metadata={
                "cve_id": cve_id,
                "source": source,
                "year": year,
                "products": products
            }
        )
        documents.append(doc)
    
    return documents

# Amélioration 2: Fonction ollama_llm modifiée pour une meilleure gestion du contexte
def ollama_llm(question: str, context: str, chat_history: List[Dict[str, str]] = None, conversation_context: ConversationContext = None) -> str:
    # Contexte par défaut si rien n'est fourni
    if not context.strip():
        # Récupérer le contexte des conversations récentes si disponible
        if conversation_context:
            recent_context = conversation_context.get_recent_context()
            if recent_context:
                context = "Contexte précédent: " + recent_context
            else:
                context = "Aucune information pertinente n'a été trouvée dans la base de données CVE."
        else:
            context = "Aucune information pertinente n'a été trouvée dans la base de données CVE."
    
    # Amélioration du prompt système pour plus de clarté et de contexte
    system_prompt = {
        'role': 'system', 
        'content': f"""
Vous êtes un expert en cybersécurité spécialisé dans les vulnérabilités CVE (Common Vulnerabilities and Exposures).
Voici quelques instructions importantes:

1. RÉPONDEZ À LA QUESTION UNIQUEMENT AVEC LES INFORMATIONS DANS LE CONTEXTE FOURNI.
2. NE FAITES PAS RÉFÉRENCE AU "CONTEXTE FOURNI" DANS VOTRE RÉPONSE.
3. SI VOUS N'AVEZ PAS SUFFISAMMENT D'INFORMATIONS, DITES SIMPLEMENT QUE VOUS N'AVEZ PAS LES DONNÉES NÉCESSAIRES.
4. MAINTENEZ LA COHÉRENCE AVEC VOS RÉPONSES PRÉCÉDENTES.
5. QUAND VOUS RÉPONDEZ SUR UN CVE SPÉCIFIQUE, INCLUEZ TOUJOURS SON ID DANS VOTRE RÉPONSE.

Contexte actuel:
{context}
"""
    }
    
    # Initialiser les messages avec le prompt système
    messages = [system_prompt]
    
    # Amélioration 3: Filtrage et limitation de l'historique de chat
    if chat_history and len(chat_history) > 0:
        # Ne garder que les 6 derniers messages pour éviter de surcharger le contexte
        filtered_history = chat_history[-6:] if len(chat_history) > 6 else chat_history
        messages.extend(filtered_history)
    
    # Ajouter la question actuelle
    messages.append({'role': 'user', 'content': question})
    
    # Faire la requête à Ollama avec température réduite pour plus de cohérence
    response = ollama.chat(
        model='llama3.1:8b', 
        messages=messages,
        options={"temperature": 0.2}  # Réduire la température pour plus de cohérence
    )
    
    return response['message']['content']

# Amélioration 4: Configuration du système RAG avec meilleure gestion du contexte
def setup_sqlite_rag(documents_directory: str, rebuild_db: bool = False):
    db_path = "cve_database.db"
    
    # Vérifier si nous devons reconstruire la base de données
    if rebuild_db or not os.path.exists(db_path):
        print("Construction d'une nouvelle base de données SQLite...")
        conn = setup_sqlite_db(db_path)
        
        start_time = time.time()
        load_cve_data_to_sqlite(documents_directory, conn)
        print(f"Base de données SQLite créée en {time.time() - start_time:.2f} secondes")
    else:
        print("Connexion à la base de données SQLite existante...")
        conn = sqlite3.connect(db_path)
    
    # Initialiser le gestionnaire de contexte de conversation
    conversation_context = ConversationContext()
    
    # Fonction pour combiner les documents
    def combine_docs(docs) -> str:
        if not docs:
            return ""
        
        result = []
        for doc in docs:
            if hasattr(doc, 'page_content'):
                result.append(doc.page_content)
            elif isinstance(doc, str):
                result.append(doc)
            elif isinstance(doc, dict) and 'page_content' in doc:
                result.append(doc['page_content'])
            else:
                result.append(str(doc))
        
        return "\n\n".join(result)
    
    # Créer/mettre à jour les tables pour l'historique des conversations
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chat_sessions (
        id INTEGER PRIMARY KEY,
        session_id TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS chat_messages (
        id INTEGER PRIMARY KEY,
        session_id INTEGER,
        role TEXT,
        content TEXT,
        cve_id TEXT,  -- Ajout d'une colonne pour stocker le CVE ID associé à ce message
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES chat_sessions(id)
    )
    ''')
    
    conn.commit()
    
    # Amélioration 5: Fonction RAG principale avec meilleure gestion du contexte
    def rag_chain(question: str, session_id: str = None):
        # Initialiser ou récupérer la session
        if not session_id:
            session_id = f"session_{int(time.time())}"
            cursor.execute('INSERT OR IGNORE INTO chat_sessions (session_id) VALUES (?)', (session_id,))
            conn.commit()
        
        # Récupérer l'ID de la session
        cursor.execute('SELECT id FROM chat_sessions WHERE session_id = ?', (session_id,))
        result = cursor.fetchone()
        if not result:
            cursor.execute('INSERT INTO chat_sessions (session_id) VALUES (?)', (session_id,))
            session_db_id = cursor.lastrowid
        else:
            session_db_id = result[0]
        
        # Récupérer l'historique du chat pour cette session
        cursor.execute('''
        SELECT role, content, cve_id FROM chat_messages 
        WHERE session_id = ? 
        ORDER BY timestamp ASC
        ''', (session_db_id,))
        
        chat_history = []
        current_cve_context = None
        
        for role, content, cve_id in cursor.fetchall():
            chat_history.append({'role': role, 'content': content})
            if cve_id:
                current_cve_context = cve_id
        
        start_time = time.time()
        
        # Amélioration 6: Détection améliorée de CVE ID dans la question
        cve_pattern = r'(CVE-\d{4}-\d{4,})|(\d{4}-\d{4,})'
        cve_matches = re.findall(cve_pattern, question, re.IGNORECASE)
        
        cve_id = None
        if cve_matches:
            # Recherche par ID CVE
            cve_id = cve_matches[0][0] if cve_matches[0][0] else cve_matches[0][1]
            if not cve_id.upper().startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"
            
            print(f"Recherche spécifique pour l'ID CVE: {cve_id}")
            retrieved_docs = get_cve_by_id(conn, cve_id)
        else:
            # Amélioration 7: Inférence du CVE à partir du contexte de la conversation
            # Rechercher si la question fait référence au CVE précédent sans le mentionner directement
            referring_expressions = ["cette cve", "ce cve", "cette vulnérabilité", "ce bulletin", 
                                   "cette faille", "cette référence", "cette entrée"]
            
            is_referring_to_previous = any(expr in question.lower() for expr in referring_expressions)
            
            if is_referring_to_previous and current_cve_context:
                print(f"Référence implicite détectée, utilisation du CVE précédent: {current_cve_context}")
                cve_id = current_cve_context
                retrieved_docs = get_cve_by_id(conn, cve_id)
            else:
                # Amélioration 8: Extraction améliorée des mots-clés
                words = re.findall(r'\b\w+\b', question.lower())
                # Liste de mots à exclure (stopwords)
                stopwords = ['what', 'when', 'where', 'which', 'who', 'why', 'how', 'about', 'does', 
                           'is', 'are', 'was', 'were', 'and', 'the', 'for', 'les', 'des', 'que', 
                           'qui', 'cette', 'ce', 'un', 'une', 'donne', 'moi', 'vous', 'tu', 'il', 
                           'elle', 'nous', 'ils', 'elles', 'sur', 'dans', 'avec', 'sans', 'mais']
                
                keywords = [word for word in words if len(word) > 3 and word.lower() not in stopwords]
                
                retrieved_docs = []
                for keyword in keywords[:3]:
                    docs = search_cve_by_keyword(conn, keyword, limit=2)
                    retrieved_docs.extend(docs)
                
                retrieved_docs = retrieved_docs[:5]
                
                # Extraire CVE ID du premier résultat pour le contexte
                if retrieved_docs and 'cve_id' in retrieved_docs[0].metadata:
                    cve_id = retrieved_docs[0].metadata['cve_id']
        
        retrieval_time = time.time() - start_time
        print(f"Récupération de {len(retrieved_docs)} documents en {retrieval_time:.2f} secondes")
        
        # Combiner les documents récupérés
        formatted_context = combine_docs(retrieved_docs)
        
        # Mettre à jour le contexte de conversation
        if cve_id and formatted_context:
            conversation_context.add_context(cve_id, formatted_context)
        
        # Génération de la réponse avec l'historique et le contexte de conversation
        start_time = time.time()
        response = ollama_llm(question, formatted_context, chat_history, conversation_context)
        generation_time = time.time() - start_time
        print(f"Génération de la réponse en {generation_time:.2f} secondes")
        
        # Sauvegarder la question et la réponse dans l'historique
        cursor.execute(
            'INSERT INTO chat_messages (session_id, role, content, cve_id) VALUES (?, ?, ?, ?)',
            (session_db_id, 'user', question, cve_id)
        )
        
        cursor.execute(
            'INSERT INTO chat_messages (session_id, role, content, cve_id) VALUES (?, ?, ?, ?)',
            (session_db_id, 'assistant', response, cve_id)
        )
        
        conn.commit()
        
        return response, session_id
    
    # Fonction pour charger une session existante
    def load_session(session_id: str):
        cursor.execute('SELECT id FROM chat_sessions WHERE session_id = ?', (session_id,))
        result = cursor.fetchone()
        if result:
            return session_id
        return None
    
    # Fonction pour lister les sessions disponibles
    def list_sessions():
        cursor.execute('''
        SELECT s.session_id, s.created_at, 
               (SELECT content FROM chat_messages WHERE session_id = s.id AND role = 'user' ORDER BY id ASC LIMIT 1) AS first_message
        FROM chat_sessions s
        ORDER BY s.created_at DESC
        ''')
        return cursor.fetchall()
    
    # Retourner les fonctions et la connexion
    return rag_chain, load_session, list_sessions, conn

if __name__ == "__main__":
    cve_directory = "cve_json_files"
    
    print("Configuration du système RAG avec SQLite...")
    rag_chain, load_session, list_sessions, conn = setup_sqlite_rag(cve_directory)
    
    # Information de débogage sur la base de données
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM cve")
        cve_count = cursor.fetchone()[0]
        print(f"Nombre de CVE dans la base: {cve_count}")
        
        # ... [Autres statistiques] ...
            
    except Exception as e:
        print(f"Erreur lors de l'inspection de la base de données: {e}")

    # Session active
    current_session_id = None
    
    # Options pour gérer les sessions
    print("\nOptions de session:")
    print("1. Créer une nouvelle session")
    print("2. Charger une session existante")
    choice = input("Votre choix (1/2, par défaut: 1): ") or "1"
    
    if choice == "2":
        sessions = list_sessions()
        if not sessions:
            print("Aucune session trouvée. Création d'une nouvelle session.")
        else:
            print("\nSessions disponibles:")
            for i, (session_id, created_at, first_msg) in enumerate(sessions):
                preview = first_msg[:40] + "..." if len(first_msg) > 40 else first_msg
                print(f"{i+1}. {created_at} - {preview}")
            
            session_choice = input("Entrez le numéro de la session à charger (ou 'n' pour nouvelle): ")
            if session_choice.lower() != 'n' and session_choice.isdigit():
                idx = int(session_choice) - 1
                if 0 <= idx < len(sessions):
                    current_session_id = load_session(sessions[idx][0])
                    print(f"Session {current_session_id} chargée.")
    
    # Boucle interactive améliorée
    print("\n=== Assistant CVE ===")
    print("Tapez 'quit' pour quitter, 'new' pour une nouvelle session, 'load' pour charger une session")
    
    # Amélioration 9: Mode de débogage pour les requêtes
    debug_mode = input("\nActiver le mode débogage (affiche le prompt complet)? (o/n, défaut: n): ").lower() == 'o'
    
    while True:
        user_question = input("\nVotre question: ")
        
        if user_question.lower() in ['quit', 'exit', 'q']:
            break
        elif user_question.lower() == 'new':
            current_session_id = None
            print("Nouvelle session créée")
            continue
        elif user_question.lower() == 'load':
            sessions = list_sessions()
            for i, (session_id, created_at, first_msg) in enumerate(sessions):
                preview = first_msg[:40] + "..." if len(first_msg) > 40 else first_msg
                print(f"{i+1}. {created_at} - {preview}")
            
            session_choice = input("Numéro de la session à charger: ")
            if session_choice.isdigit():
                idx = int(session_choice) - 1
                if 0 <= idx < len(sessions):
                    current_session_id = load_session(sessions[idx][0])
                    print(f"Session {current_session_id} chargée.")
            continue
        
        start_time = time.time()
        result, current_session_id = rag_chain(user_question, current_session_id)
        total_time = time.time() - start_time
        
        print("\nRéponse:")
        print(result)
        print(f"\nTemps total de traitement: {total_time:.2f} secondes")
        print(f"Session active: {current_session_id}")
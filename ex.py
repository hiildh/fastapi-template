from fastapi import FastAPI, HTTPException, Depends, Query
from firebase_admin import credentials, initialize_app, db
import pyrebase
import uuid
import os
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any

load_dotenv()

# Configurações
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_DAYS = 365  # Token válido por 1 ano

# Configurações do Pyrebase (para autenticação)
firebase_config = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "databaseURL": "https://shopping-lists-2b820-default-rtdb.firebaseio.com/",
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID")
}

firebase = pyrebase.initialize_app(firebase_config)
auth = firebase.auth()

security = HTTPBearer()

# Firebase
cred = credentials.Certificate("firebase-credentials.json")
initialize_app(cred, {
    'databaseURL': os.getenv("FIREBASE_DATABASE_URL", "https://shopping-lists-2b820-default-rtdb.firebaseio.com/")
})

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://192.168.3.9", "http://localhost", "http://192.168.3.59"],  # Substitua pelo IP correto
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Helpers ---
def generate_id():
    return str(uuid.uuid4())[:8].upper()

def generate_family_code():
    return str(uuid.uuid4())[:6].upper()

def create_access_token(uid: str):
    expires = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    payload = {"sub": uid, "exp": expires}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        
        # Verifica se o usuário existe
        if not db.reference(f"users/{uid}").get():
            raise HTTPException(404, "Usuário não encontrado")
        
        return uid
    except JWTError:
        raise HTTPException(401, "Token inválido")

# --- Models ---
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ShoppingListItem(BaseModel):
    nome: str
    by_user: Optional[str] = None
    checado: bool = False

class ShoppingListCreate(BaseModel):
    nome: str
    familia: Optional[str] = None
    itens: Optional[List[ShoppingListItem]] = []

class ShoppingListStatusUpdate(BaseModel):
    status: str  # "concluida", "cancelada", "incompleta"

class ShoppingListItemCreate(BaseModel):
    nome: str

class ShoppingListItemUpdate(BaseModel):
    checado: bool

class ShoppingListItemsAdd(BaseModel):
    itens: List[ShoppingListItem]

# --- Endpoints ---
@app.post("/register")
async def register(user_data: UserCreate):
    print("Dados recebidos:", user_data)
    try:
        # 1. Cria usuário no Firebase Authentication (Pyrebase)
        try:
            user = auth.create_user_with_email_and_password(
                user_data.email, 
                user_data.password
            )
            print("Usuário criado no Firebase:", user)
        except Exception as e:
            print("Erro ao criar usuário no Firebase:", str(e))
            raise HTTPException(400, {"message": str(e)})
        
        # 2. Cria família automaticamente (Firebase Admin)
        family_id = generate_id()
        family_code = generate_family_code()
        
        db.reference(f"families/{family_id}").set({
            "name": f"Família de {user_data.name}",
            "code": family_code,
            "owner": user["localId"],
            "members": {user["localId"]: True}
        })

        # Salva usuário com a família própria
        db.reference(f"users/{user['localId']}").set({
            "name": user_data.name, 
            "email": user_data.email,
            "families": {family_id: True}  # Agora é um objeto!
        })

        # 4. Gera token JWT
        token = create_access_token(user["localId"])
        return {"access_token": token, "family_id": family_id, "name": user_data.name}

    except Exception as e:
        print("Erro ao criar usuário no Firebase:", str(e))
        raise HTTPException(400, {"message": str(e)})

@app.post("/login")
async def login(user_data: UserLogin):
    try:
        user = auth.sign_in_with_email_and_password(user_data.email, user_data.password)
        token = create_access_token(user["localId"])
        user_data = db.reference(f"users/{user['localId']}").get()
        return {"access_token": token, "name": user_data.get("name"), "family_id": list(user_data.get("families", {}).keys())[0]}
    
    except Exception as e:
        raise HTTPException(401, "Credenciais inválidas")

@app.post("/families/join")
async def join_family(
    code: str, 
    current_user_id: str = Depends(get_current_user)
):
    try:
        # 1. Busca a família pelo código
        families_ref = db.reference("families")
        query_result = families_ref.order_by_child("code").equal_to(code).get()

        if not query_result:
            raise HTTPException(status_code=404, detail="Código inválido")

        # Extrai o ID da família
        family_id = next(iter(query_result))  # Pega a primeira chave
        family_data = query_result[family_id]

        # 2. Verifica se o usuário já é membro
        if family_data.get("members", {}).get(current_user_id):
            raise HTTPException(400, "Você já está nesta família")

        # 3. Adiciona o usuário à família
        # - Atualiza a lista de famílias do usuário
        user_ref = db.reference(f"users/{current_user_id}/families")
        user_ref.update({family_id: True})  # Adiciona sem apagar as existentes

        # 4. Adiciona à nova família
        db.reference(f"families/{family_id}/members/{current_user_id}").set(True)

        return {"message": "Você entrou na família!", "family_id": family_id}

    except StopIteration:
        raise HTTPException(404, "Família não encontrada")
    except Exception as e:
        raise HTTPException(500, f"Erro: {str(e)}")

@app.get("/users/me/families")
async def get_my_families(current_user_id: str = Depends(get_current_user)):
    user_data = db.reference(f"users/{current_user_id}").get()
    families = user_data.get("families", {})
    return {"families": list(families.keys())}

@app.get("/families/{family_id}/members")
async def get_family_members(family_id: str):
    family_data = db.reference(f"families/{family_id}").get()
    if not family_data:
        raise HTTPException(404, "Família não encontrada")
    return {"members": list(family_data.get("members", {}).keys())}

# --- NOVAS FUNCIONALIDADES ---

# 2 - LISTA DE COMPRAS

@app.get("/shopping-lists")
async def get_shopping_lists(
    family_id: str, 
    q: Optional[str] = None,
    current_user_id: str = Depends(get_current_user)
):
    """
    Retorna todas as listas de compras incompletas de uma família.
    Opcionalmente, pode filtrar por nome da lista.
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Obtém todas as listas da família
        lists_ref = db.reference(f"shopping_lists/{family_id}")
        lists = lists_ref.get() or {}
        
        # Filtra apenas as listas incompletas
        incomplete_lists = {}
        for list_id, list_data in lists.items():
            if list_data.get("status", "incompleta") == "incompleta":
                # Filtra por nome se o parâmetro de busca estiver presente
                if q is None or q.lower() in list_data.get("nome", "").lower():
                    incomplete_lists[list_id] = list_data
        
        return {"lists": incomplete_lists}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao obter listas: {str(e)}")

@app.post("/shopping-lists")
async def create_shopping_list(
    shopping_list: ShoppingListCreate,
    current_user_id: str = Depends(get_current_user)
):
    """
    Cria uma nova lista de compras para uma família.
    """
    try:
        # Verifica se a família existe e se o usuário pertence a ela
        family_id = shopping_list.familia
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        
        if not family_id:
            # Se não especificou família, usa a primeira do usuário
            if not user_families:
                raise HTTPException(400, "Usuário não possui famílias")
            family_id = next(iter(user_families.keys()))
        elif family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Gera ID para a nova lista
        list_id = generate_id()
        
        # Prepara os itens adicionando o by_user
        itens = []
        for item in shopping_list.itens:
            item_dict = item.dict()
            item_dict["by_user"] = current_user_id
            itens.append(item_dict)
        
        # Cria a nova lista
        current_date = datetime.now().isoformat()
        list_data = {
            "nome": shopping_list.nome,
            "data": current_date,
            "by_user": current_user_id,
            "usuarios_vinculados_lista": {current_user_id: True},
            "familia": family_id,
            "itens": itens,
            "status": "incompleta"
        }
        
        db.reference(f"shopping_lists/{family_id}/{list_id}").set(list_data)
        
        return {"id": list_id, "data": list_data}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao criar lista: {str(e)}")

@app.patch("/shopping-lists/{family_id}/{list_id}")
async def update_shopping_list_status(
    family_id: str,
    list_id: str,
    status_update: ShoppingListStatusUpdate,
    current_user_id: str = Depends(get_current_user)
):
    """
    Atualiza o status de uma lista de compras (concluída, cancelada, incompleta).
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Verifica se a lista existe
        list_ref = db.reference(f"shopping_lists/{family_id}/{list_id}")
        list_data = list_ref.get()
        
        if not list_data:
            raise HTTPException(404, "Lista não encontrada")
        
        # Valida o status
        status = status_update.status.lower()
        if status not in ["concluida", "cancelada", "incompleta"]:
            raise HTTPException(400, "Status inválido. Use 'concluida', 'cancelada' ou 'incompleta'")
        
        # Atualiza o status
        list_ref.update({"status": status})
        
        return {"message": f"Status da lista atualizado para {status}"}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao atualizar status: {str(e)}")

# 3 - ITENS DA LISTA

@app.get("/shopping-lists/{family_id}/{list_id}/items")
async def get_shopping_list_items(
    family_id: str,
    list_id: str,
    current_user_id: str = Depends(get_current_user)
):
    """
    Retorna todos os itens de uma lista de compras.
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Verifica se a lista existe
        list_ref = db.reference(f"shopping_lists/{family_id}/{list_id}")
        list_data = list_ref.get()
        
        if not list_data:
            raise HTTPException(404, "Lista não encontrada")
        
        # Retorna os itens da lista
        items = list_data.get("itens", [])
        
        return {"items": items}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao obter itens: {str(e)}")

@app.post("/shopping-lists/{family_id}/{list_id}/items")
async def add_items_to_shopping_list(
    family_id: str,
    list_id: str,
    items_add: ShoppingListItemsAdd,
    current_user_id: str = Depends(get_current_user)
):
    """
    Adiciona itens a uma lista de compras.
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Verifica se a lista existe
        list_ref = db.reference(f"shopping_lists/{family_id}/{list_id}")
        list_data = list_ref.get()
        
        if not list_data:
            raise HTTPException(404, "Lista não encontrada")
        
        # Se a lista estiver concluída ou cancelada, muda para incompleta
        if list_data.get("status") in ["concluida", "cancelada"]:
            list_ref.update({"status": "incompleta"})
        
        # Adiciona os itens à lista
        current_items = list_data.get("itens", [])
        
        for item in items_add.itens:
            item_dict = item.dict()
            item_dict["by_user"] = current_user_id
            current_items.append(item_dict)
        
        # Atualiza a lista no Firebase
        list_ref.update({"itens": current_items})
        
        return {"message": f"{len(items_add.itens)} itens adicionados à lista"}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao adicionar itens: {str(e)}")

@app.patch("/shopping-lists/{family_id}/{list_id}/items/{item_index}")
async def update_shopping_list_item(
    family_id: str,
    list_id: str,
    item_index: int,
    item_update: ShoppingListItemUpdate,
    current_user_id: str = Depends(get_current_user)
):
    """
    Atualiza o status de um item da lista (checado ou não).
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Verifica se a lista existe
        list_ref = db.reference(f"shopping_lists/{family_id}/{list_id}")
        list_data = list_ref.get()
        
        if not list_data:
            raise HTTPException(404, "Lista não encontrada")
        
        # Verifica se o item existe
        items = list_data.get("itens", [])
        if item_index < 0 or item_index >= len(items):
            raise HTTPException(404, "Item não encontrado")
        
        # Atualiza o item
        items[item_index]["checado"] = item_update.checado
        
        # Se a lista estiver concluída ou cancelada e um item for desmarcado, muda para incompleta
        if not item_update.checado and list_data.get("status") in ["concluida", "cancelada"]:
            list_ref.update({"status": "incompleta"})
        
        # Atualiza a lista no Firebase
        list_ref.update({"itens": items})
        
        return {"message": "Item atualizado"}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao atualizar item: {str(e)}")

@app.delete("/shopping-lists/{family_id}/{list_id}/items/{item_index}")
async def delete_shopping_list_item(
    family_id: str,
    list_id: str,
    item_index: int,
    current_user_id: str = Depends(get_current_user)
):
    """
    Remove um item da lista de compras.
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Verifica se a lista existe
        list_ref = db.reference(f"shopping_lists/{family_id}/{list_id}")
        list_data = list_ref.get()
        
        if not list_data:
            raise HTTPException(404, "Lista não encontrada")
        
        # Verifica se o item existe
        items = list_data.get("itens", [])
        if item_index < 0 or item_index >= len(items):
            raise HTTPException(404, "Item não encontrado")
        
        # Remove o item
        removed_item = items.pop(item_index)
        
        # Atualiza a lista no Firebase
        list_ref.update({"itens": items})
        
        return {"message": f"Item '{removed_item['nome']}' removido da lista"}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao remover item: {str(e)}")

@app.get("/items/suggestions")
async def get_item_suggestions(
    q: str = Query(..., min_length=1),
    family_id: Optional[str] = None,
    current_user_id: str = Depends(get_current_user)
):
    """
    Retorna sugestões de itens com base no texto de busca.
    Usa o histórico de itens da família ou do usuário para sugerir produtos semelhantes.
    """
    try:
        suggestions = []
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        
        # Se não especificou família, procura em todas as famílias do usuário
        families_to_search = [family_id] if family_id else user_families.keys()
        
        for fid in families_to_search:
            if fid not in user_families:
                continue  # Pula se o usuário não pertencer à família
            
            # Busca todas as listas da família
            lists_ref = db.reference(f"shopping_lists/{fid}")
            all_lists = lists_ref.get() or {}
            
            # Percorre todas as listas
            for list_data in all_lists.values():
                for item in list_data.get("itens", []):
                    if q.lower() in item.get("nome", "").lower() and item.get("nome") not in suggestions:
                        suggestions.append(item.get("nome"))
        
        return {"suggestions": suggestions[:10]}  # Limita a 10 sugestões
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao buscar sugestões: {str(e)}")

# 4 - HISTÓRICO

@app.get("/shopping-lists/history")
async def get_shopping_lists_history(
    family_id: str,
    current_user_id: str = Depends(get_current_user)
):
    """
    Retorna o histórico de listas de compras concluídas ou canceladas.
    """
    try:
        # Verifica se o usuário pertence à família
        user_families = db.reference(f"users/{current_user_id}/families").get() or {}
        if family_id not in user_families:
            raise HTTPException(403, "Você não tem acesso a esta família")
        
        # Obtém todas as listas da família
        lists_ref = db.reference(f"shopping_lists/{family_id}")
        lists = lists_ref.get() or {}
        
        # Filtra apenas as listas concluídas ou canceladas
        history_lists = {}
        for list_id, list_data in lists.items():
            status = list_data.get("status", "")
            if status in ["concluida", "cancelada"]:
                history_lists[list_id] = list_data
        
        # Ordena por data (mais recente primeiro)
        sorted_history = dict(sorted(
            history_lists.items(), 
            key=lambda item: item[1].get("data", ""), 
            reverse=True
        ))
        
        return {"history": sorted_history}
    
    except Exception as e:
        raise HTTPException(500, f"Erro ao obter histórico: {str(e)}")

# Verifica o token do usuário
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        
        # Verifica se o usuário existe
        if not db.reference(f"users/{uid}").get():
            raise HTTPException(404, "Usuário não encontrado")
        
        return uid
    except JWTError:
        raise HTTPException(401, "Token inválido")
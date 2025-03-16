from fastapi import FastAPI, HTTPException, Depends
from firebase_admin import credentials, initialize_app, db
import pyrebase
import uuid
import os
from pydantic import BaseModel
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

# Configurações
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_DAYS = 365  # Token válido por 1 ano

# Configurações do Pyrebase (para autenticação)
firebase_config = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "databaseURL": "https://lista-compras-2b820-default-rtdb.firebaseio.com/",
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
    'databaseURL': 'https://lista-compras-2b820-default-rtdb.firebaseio.com/'
})

app = FastAPI()

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

# --- Endpoints ---
@app.post("/register")
async def register(user_data: UserCreate):
    try:
        # 1. Cria usuário no Firebase Authentication (Pyrebase)
        user = auth.create_user_with_email_and_password(
            user_data.email, 
            user_data.password
        )
        
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
        return {"access_token": token, "family_id": family_id}

    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/login")
async def login(user_data: UserLogin):
    try:
        user = auth.sign_in_with_email_and_password(user_data.email, user_data.password)
        token = create_access_token(user["localId"])
        return {"access_token": token}
    
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
    

# --- Função para verificar token ---
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
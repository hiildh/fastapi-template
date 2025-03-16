# FastAPI Template

Este é um template para iniciar um projeto com FastAPI.

## Como rodar a API localmente

Siga os passos abaixo para rodar a API localmente:

### Pré-requisitos

- Python 3.7 ou superior
- pip (gerenciador de pacotes do Python)
- virtualenv (opcional, mas recomendado)

### Passos

1. **Clone o repositório:**

    ```bash
    git clone https://github.com/hiildh/fastapi-template.git
    cd fastapi-template
    ```

2. **Crie um ambiente virtual (opcional, mas recomendado):**

    ```bash
    python -m venv venv
    source venv/bin/activate  # No Windows use `venv\Scripts\activate`
    ```

3. **Instale as dependências:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Execute a aplicação:**

    ```bash
    uvicorn main:app --reload
    ```

    A aplicação estará disponível em [http://127.0.0.1:8000](http://127.0.0.1:8000).

### Estrutura do Projeto

- `main.py`: Arquivo principal da aplicação FastAPI.
- `requirements.txt`: Arquivo com as dependências do projeto.

### Endpoints

Você pode acessar a documentação interativa da API em [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) após iniciar a aplicação.

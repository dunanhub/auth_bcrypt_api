# 🔐 auth_bcrypt_api

> API для безопасной регистрации и логина пользователей с использованием bcrypt-хеширования.

---

## 🚀 Возможности

✅ Регистрация пользователя (`POST /register`)  
✅ Логин с проверкой хешированного пароля (`POST /login`)  
✅ Безопасное хранение паролей (Passlib + bcrypt)  
✅ Асинхронная работа с PostgreSQL  
✅ Тестирование через Postman

---

## 🧰 Технологии

- [FastAPI](https://fastapi.tiangolo.com/)
- [SQLModel](https://sqlmodel.tiangolo.com/)
- [PostgreSQL](https://www.postgresql.org/)
- [Passlib (bcrypt)](https://passlib.readthedocs.io/)
- [Uvicorn](https://www.uvicorn.org/)
- [asyncpg](https://magicstack.github.io/asyncpg/)
- [Pydantic](https://docs.pydantic.dev/)
- [Postman](https://www.postman.com/)

---

## 🛠️ Установка

```bash
# 📁 Клонируй репозиторий
git clone https://github.com/your-username/auth_bcrypt_api.git
cd auth_bcrypt_api
```

```bash
# 🧪 Создай виртуальное окружение

python -m venv .venv
.venv\Scripts\activate # Windows

# или

python3 -m venv .venv
source .venv/bin/activate # macOS/Linux
```

```bash
# 📦 Установи зависимости
pip install -r requirements.txt
```

```env
# ⚙️ Настрой файл .env
DATABASE_URL=postgresql+asyncpg://postgres:your_password@localhost:5432/auth_bcrypt_api
```

```bash
# 🚀 Запусти FastAPI приложение
uvicorn app.main:app --reload
```

---

## 📬 Примеры API-запросов

### ➕ POST `/register` — Регистрация:

```http
POST http://localhost:8000/notes
```

```json
{
  "username": "user",
  "password": "1234"
}
```

### 📥 GET `/login` — Логин:

```http
POST http://localhost:8000/login
```

```json
[
  {
    "username": "user",
    "password": "1234"
  }
]
```

---

## 📂 Структура проекта

```
auth_bcrypt_api/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── routes.py
│   └── utils.py
├── .env
├── requirements.txt
├── README.md
└── LICENSE
```

---

## ⚖️ Лицензия

Этот проект лицензирован под MIT. См. файл [LICENSE](./LICENSE) для подробностей.

# Технологии Разработки Серверных Приложений

## Контрольная работа № 3

> Выполнил: Солдатов Александр, ЭФБО-04-24
---

Установка и запуск:

Обновить .env

```bash
pip install fastapi uvicorn sqlalchemy bcrypt python-jose[cryptography] python-dotenv slowapi
uvicorn main:app --reload
```

---

# Проверка работоспособности через curl:

# Проверка работы сервера

```bash
curl http://localhost:8000/
```

```json
{
  "status": "ok",
  "mode": "DEV"
}
```

# Регистрация пользователяи

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "correctpass"}' \
  http://localhost:8000/register-basic
```

```json
{
  "message": "New user created"
}
```

# Вход с правильными учетными данными

```bash
curl -u user1:correctpass http://localhost:8000/login-basic
```

```json
{
  "message": "Welcome, user1!"
}
```

# Вход с неправильным паролем

```bash
curl -u user1:wrongpass http://localhost:8000/login-basic
```

```json
{
  "detail": "Not Found"
}
```

# Вход в систему (получение JWT токена)

```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "qwerty123"}' \
  http://localhost:8000/login
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTc3NjA3MjM4MH0.X2T1xEveAGbpYralvSUeMEAnflM9rwokiB3E-OhKsRc",
  "token_type": "bearer"
}
```

# Доступ к защищенному ресурсу

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/protected-resource
```

```json
{
  "message": "Access granted to user"
}
```

# Доступ к ресурсу для администраторов (будет отказано)

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/admin-only
```

```json
{
  "detail": "Access denied"
}
```

# Создание задачи

```bash
curl -X POST http://localhost:8000/todos \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Купить продукты","description":"Молоко, хлеб, яйца"}'
```

```json
{
  "id": 1,
  "title": "Купить продукты",
  "description": "Молоко, хлеб, яйца",
  "completed": false
}
```

# Получение всех задач

```bash
curl http://localhost:8000/todos/
```

```json
[
  {
    "id": 1,
    "title": "Купить продукты",
    "description": "Молоко, хлеб, яйца",
    "completed": false
  }
]
```

# Обновление задачи

```bash
curl -X PUT -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"completed": true}' \
  http://localhost:8000/todos/1
```

```json
{
  "id": 1,
  "title": "Купить продукты",
  "description": "Молоко, хлеб, яйца",
  "completed": true
}
```

# Удаление задачи (только для администраторов)

```bash
curl http://localhost:8000/todos/
```

# DEV-режим: Доступ к Swagger UI

```bash
curl -u admin:secret http://localhost:8000/docs
```

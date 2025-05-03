# Лабораторная работа 3 — JWT авторизация в FastAPI

## 📌 Что реализовано

- Получение токена (`/token`)
- Защищённый маршрут `/users/me`
- Верификация и декодирование JWT

## ▶ Как запустить

1. Установи зависимости:
   ```
   pip install -r requirements.txt
   ```

2. Запусти сервер:
   ```
   uvicorn main:app --reload
   ```

3. Перейди в браузере:
   ```
   http://127.0.0.1:8000/docs
   ```

## ✅ Как протестировать

1. Перейди в Swagger UI.
2. Нажми **Authorize**, введи:
   - `username`: john
   - `password`: secret
3. Получи токен и вызови `/users/me`

## 🧠 Как выложить на GitHub

```bash
git init
git add .
git commit -m "lab3 — JWT"
git branch -M main
git remote add origin https://github.com/ТВОЙ_ЛОГИН/lab3-jwt.git
git push -u origin main
```

# Blog Médico (Demo) — Flask “Vintage” + Docker
#test
Demo estilo 2014–2016: server-rendered con Flask, SQLite, templates, RSS y panel admin clásico.

## Features (vintage)
- Tags (many-to-many) y vista por tag: `/tag/<name>`
- Búsqueda simple (SQL LIKE): `/search?q=...` (con paginación)
- Archivo por mes: `/archive/<year>/<month>`
- RSS: `/feed.xml`
- Admin:
  - Draft / Published
  - Scheduled publish (`publish_at` futuro no se ve en público)
  - Soft delete
  - Moderación de comentarios

## Aviso médico
Contenido informativo / educativo. No sustituye diagnóstico ni consulta médica.

## Correr con Docker
```bash
docker compose up --build
```

- Blog: http://localhost:8000/
- Login: http://localhost:8000/login
- Admin: http://localhost:8000/admin
- Comentarios: http://localhost:8000/admin/comments
- RSS: http://localhost:8000/feed.xml

## Credenciales
- user: `admin`
- password: `ADMIN_PASSWORD` (por defecto `admin123` en `docker-compose.yml`)

## Persistencia
SQLite en `/data/blog.db` (volume `blogdata`).

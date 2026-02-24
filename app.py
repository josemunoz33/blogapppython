import json
import logging
import os
import random
import secrets
import sys
from datetime import UTC, datetime, timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, Response, abort, flash, redirect, render_template, request, url_for
from flask.cli import with_appcontext
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import func, or_, select
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from forms import CommentForm, LoginForm, ModerateCommentForm, PostForm


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
        }
        for key in (
            "event",
            "method",
            "path",
            "status_code",
            "ip",
            "ua",
            "user",
            "action",
            "comment_id",
            "post_id",
            "slug",
        ):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def utcnow_naive() -> datetime:
    """Return UTC datetime stored as naive (UTC) for SQLite compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)


def normalize_database_url(url: str) -> str:
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql://", 1)
    return url


def get_client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "-"


def parse_page_arg() -> int:
    raw_page = request.args.get("page", "1")
    try:
        page = int(raw_page)
    except (TypeError, ValueError):
        page = 1
    return max(page, 1)


# -----------------------------------------------------------------------------
# App / Extensions setup
# -----------------------------------------------------------------------------

app = Flask(__name__)
# Behind DigitalOcean App Platform / reverse proxies.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# --- Logging setup (stdout + optional file) ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "json").lower()  # json|text


def _make_formatter() -> logging.Formatter:
    if LOG_FORMAT == "json":
        return JsonFormatter()
    return logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")


stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(LOG_LEVEL)
stream_handler.setFormatter(_make_formatter())

app.logger.handlers.clear()
app.logger.setLevel(LOG_LEVEL)
app.logger.addHandler(stream_handler)
app.logger.propagate = False

if as_bool(os.environ.get("ENABLE_FILE_LOG"), default=False):
    os.makedirs("/data/logs", exist_ok=True)
    file_handler = RotatingFileHandler(
        "/data/logs/app.log", maxBytes=2_000_000, backupCount=3
    )
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(_make_formatter())
    app.logger.addHandler(file_handler)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    # Safer default than a static hard-coded secret, but still logged as warning.
    secret_key = secrets.token_urlsafe(32)
    app.logger.warning(
        "SECRET_KEY_missing_ephemeral",
        extra={"event": "config_warning", "action": "generated_ephemeral_secret"},
    )

app.config.update(
    SECRET_KEY=secret_key,
    SQLALCHEMY_DATABASE_URI=normalize_database_url(
        os.environ.get("DATABASE_URL", "sqlite:////data/blog.db")
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1MB
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=as_bool(os.environ.get("SESSION_COOKIE_SECURE"), default=False),
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
    REMEMBER_COOKIE_SECURE=as_bool(os.environ.get("SESSION_COOKIE_SECURE"), default=False),
    WTF_CSRF_TIME_LIMIT=60 * 60 * 4,
)

trusted_hosts = [h.strip() for h in os.environ.get("TRUSTED_HOSTS", "").split(",") if h.strip()]
if trusted_hosts:
    app.config["TRUSTED_HOSTS"] = trusted_hosts

# Flask-SQLAlchemy / Flask-Login / CSRF

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "error"
csrf = CSRFProtect(app)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------

post_tags = db.Table(
    "post_tags",
    db.Column("post_id", db.Integer, db.ForeignKey("post.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tag.id"), primary_key=True),
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<Tag {self.name}>"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    slug = db.Column(db.String(220), unique=True, nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(20), nullable=False, default="published")  # draft|published
    publish_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive, index=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive, onupdate=utcnow_naive)

    views = db.Column(db.Integer, nullable=False, default=0)

    tags = db.relationship(
        "Tag",
        secondary=post_tags,
        lazy="subquery",
        backref=db.backref("posts", lazy=True),
    )
    comments = db.relationship(
        "Comment",
        backref="post",
        cascade="all, delete-orphan",
        order_by="Comment.created_at.asc()",
    )

    def __repr__(self) -> str:
        return f"<Post {self.slug}>"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False, index=True)
    author = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_approved = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow_naive, index=True)


MAX_AUTHOR_LEN = 60
MAX_COMMENT_LEN = 1000
MAX_TITLE_LEN = 180
MAX_SLUG_LEN = 220
MAX_POST_LEN = 30_000


# -----------------------------------------------------------------------------
# Domain helpers
# -----------------------------------------------------------------------------

def simple_slugify(text: str | None) -> str:
    value = (text or "").strip().lower()
    output: list[str] = []
    for ch in value:
        if ch.isalnum():
            output.append(ch)
        elif ch in {" ", "-", "_"}:
            output.append("-")
    slug = "".join(output)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "post"


def excerpt(text: str | None, n: int = 240) -> str:
    clean = (text or "").strip()
    return clean if len(clean) <= n else f"{clean[:n].rstrip()}..."


def parse_tags(tag_str: str | None) -> list[str]:
    raw_tags = (tag_str or "").split(",")
    parsed: list[str] = []
    for tag in raw_tags:
        normalized = tag.strip().lower()
        if normalized:
            parsed.append(normalized[:40])

    seen: set[str] = set()
    unique: list[str] = []
    for tag in parsed:
        if tag not in seen:
            unique.append(tag)
            seen.add(tag)
    return unique[:12]


def upsert_tags(tag_names: list[str]) -> list[Tag]:
    tags: list[Tag] = []
    for name in tag_names:
        tag = db.session.scalar(select(Tag).where(Tag.name == name))
        if tag is None:
            tag = Tag(name=name)
            db.session.add(tag)
        tags.append(tag)
    return tags


def visible_posts_stmt():
    return (
        select(Post)
        .where(Post.is_deleted.is_(False))
        .where(Post.status == "published")
        .where(Post.publish_at <= utcnow_naive())
    )


def paginate_posts(stmt, page: int, per_page: int = 8):
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = db.session.scalar(count_stmt) or 0
    pages = max((total + per_page - 1) // per_page, 1)
    page = min(max(page, 1), pages)

    items = db.session.scalars(
        stmt.order_by(Post.publish_at.desc()).limit(per_page).offset((page - 1) * per_page)
    ).all()
    return items, page, pages, total


def build_archive_months(limit: int = 6) -> list[tuple[int, int]]:
    months: list[tuple[int, int]] = []
    cursor = utcnow_naive().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for _ in range(limit):
        months.append((cursor.year, cursor.month))
        cursor = (cursor - timedelta(days=1)).replace(day=1)
    return months


def get_sidebar_context() -> dict:
    latest = db.session.scalars(visible_posts_stmt().order_by(Post.publish_at.desc()).limit(6)).all()
    tag_cloud = db.session.scalars(select(Tag).order_by(Tag.name.asc()).limit(24)).all()
    return {"latest": latest, "tag_cloud": tag_cloud, "months": build_archive_months(6)}


app.jinja_env.globals.update(excerpt=excerpt)


# -----------------------------------------------------------------------------
# Request / response hooks
# -----------------------------------------------------------------------------

@app.before_request
def log_request_info():
    app.logger.info(
        "request",
        extra={
            "event": "request",
            "method": request.method,
            "path": request.path,
            "ip": get_client_ip(),
            "ua": (request.headers.get("User-Agent", "-") or "-")[:180],
        },
    )


@app.after_request
def add_headers_and_log(response):
    # Security headers (compatible with inline styles currently used in templates)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'",
    )
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    # Avoid caching authenticated admin pages.
    if current_user.is_authenticated and request.path.startswith("/admin"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    app.logger.info(
        "response",
        extra={
            "event": "response",
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "ip": get_client_ip(),
        },
    )
    return response


# -----------------------------------------------------------------------------
# Login / CLI
# -----------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id: str):
    try:
        numeric_id = int(user_id)
    except (TypeError, ValueError):
        return None
    return db.session.get(User, numeric_id)


@app.cli.command("initdb")
@with_appcontext
def initdb():
    os.makedirs("/data", exist_ok=True)
    db.create_all()

    if db.session.scalar(select(User).where(User.username == "admin")):
        print("Admin user already exists.")
        return

    admin_password = os.environ.get("ADMIN_PASSWORD", "admin123")
    admin_user = User(
        username="admin",
        password_hash=generate_password_hash(admin_password),
    )
    db.session.add(admin_user)
    db.session.commit()

    print("Created admin user: admin")
    print("Password source: ADMIN_PASSWORD env (or default if not provided).")


TOPICS = [
    "prevención",
    "nutrición",
    "salud mental",
    "cardiología",
    "diabetes",
    "dermatología",
    "pediatría",
    "ejercicio",
    "sueño",
    "vacunas",
    "primeros auxilios",
    "salud pública",
    "hipertensión",
    "hábitos",
]
TITLES = [
    "Guía práctica: hábitos saludables que sí sostienen",
    "Sueño y salud: 7 ajustes simples para descansar mejor",
    "Nutrición básica: plato balanceado sin complicarte",
    "Hipertensión: señales, medición en casa y mitos comunes",
    "Diabetes tipo 2: prevención y seguimiento en el día a día",
    "Salud mental: estrategias de autocuidado (sin romantizar)",
    "Ejercicio para principiantes: empezar sin lesionarte",
    "Vacunas: cómo pensar en riesgo y beneficio (explicado fácil)",
    "Primeros auxilios: lo que conviene tener en casa",
    "Dermatología: cuidado de piel básico para clima tropical",
]
PARA = [
    "Este artículo es informativo y no reemplaza una consulta médica. Si tienes síntomas, dolor fuerte, fiebre persistente o dudas, consulta a un profesional.",
    "En salud, lo que funciona suele ser lo que puedes mantener: pequeñas mejoras, consistentes, con seguimiento y ajuste.",
    "Si vas a cambiar medicación, dieta o rutinas por una condición médica, es mejor hacerlo con guía profesional y monitoreo.",
    "Un buen enfoque: define objetivo, mide una línea base, cambia una variable a la vez y revisa resultados cada 2–4 semanas.",
    "Recuerda el contexto: edad, antecedentes familiares, sueño, estrés, actividad y alimentación afectan el resultado.",
]
LISTS = [
    [
        "Hidrátate de forma regular (sin extremos).",
        "Incluye proteína en comidas principales.",
        "Camina 20–30 min, 4–5 días/semana.",
        "Evita “todo o nada”: apunta a constancia.",
        "Haz chequeos si tienes antecedentes familiares.",
    ],
    [
        "Rutina de sueño consistente (hora fija).",
        "Luz solar en la mañana 10–15 min.",
        "Pantallas fuera 60 min antes de dormir.",
        "Cafeína solo temprano.",
        "Cuarto fresco y oscuro.",
    ],
    [
        "Aprende a leer etiquetas simples.",
        "Aumenta fibra (frutas, vegetales, legumbres).",
        "Reduce ultraprocesados gradualmente.",
        "No ‘demonices’ grupos enteros de alimentos.",
        "Planifica snacks sencillos (yogurt, fruta, nueces).",
    ],
]


def make_post_body() -> str:
    parts: list[str] = []
    parts.append(PARA[0])
    parts.append("")
    parts.append("## Resumen")
    parts.append(random.choice(PARA[1:]))
    parts.append("")
    parts.append("## Puntos clave")
    for bullet in random.choice(LISTS):
        parts.append(f"- {bullet}")
    parts.append("")
    parts.append("## Nota final")
    parts.append(
        "Si quieres, lleva un registro (presión, sueño, pasos, glucosa si aplica) y revisa tendencias. Lo importante es el progreso, no la perfección."
    )
    return "\n".join(parts)


@app.cli.command("seed")
@with_appcontext
def seed():
    os.makedirs("/data", exist_ok=True)
    db.create_all()
    if (db.session.scalar(select(func.count()).select_from(Post)) or 0) > 8:
        print("Seed skipped (already has data).")
        return

    for i in range(18):
        title = TITLES[i % len(TITLES)]
        slug = simple_slugify(title)
        base_slug = slug
        n = 2
        while db.session.scalar(select(Post).where(Post.slug == slug)):
            slug = f"{base_slug}-{n}"
            n += 1

        status = "published" if i % 6 != 0 else "draft"
        publish_at = utcnow_naive() - timedelta(days=random.randint(0, 150))
        if i in (2, 11):
            publish_at = utcnow_naive() + timedelta(days=random.randint(2, 12))

        post = Post(
            title=title,
            slug=slug,
            content=make_post_body(),
            status=status,
            publish_at=publish_at,
            created_at=publish_at,
            updated_at=publish_at,
        )
        post.tags = upsert_tags(random.sample(TOPICS, k=random.randint(2, 4)))
        db.session.add(post)
        db.session.flush()

        for _ in range(random.randint(0, 5)):
            comment = Comment(
                post_id=post.id,
                author=random.choice(
                    ["Paciente", "Visitante", "Ana", "Luis", "ClínicaXYZ", "Admin"]
                ),
                body="Gracias por el artículo. Muy claro. ¿Recomiendas algún recurso adicional para profundizar?",
                is_approved=(random.randint(0, 10) != 0),
            )
            db.session.add(comment)

    db.session.commit()
    print("Seeded medical posts, tags and comments.")


# -----------------------------------------------------------------------------
# Routes (public)
# -----------------------------------------------------------------------------

@app.route("/")
def index():
    page = parse_page_arg()
    posts, page, pages, total = paginate_posts(visible_posts_stmt(), page=page, per_page=8)

    return render_template(
        "index.html",
        posts=posts,
        page=page,
        pages=pages,
        total=total,
        **get_sidebar_context(),
    )


@app.route("/p/<slug>", methods=["GET", "POST"])
def post_view(slug: str):
    post = db.session.scalar(visible_posts_stmt().where(Post.slug == slug))
    if post is None:
        abort(404)

    # Lightweight counter update.
    post.views = (post.views or 0) + 1
    db.session.commit()

    form = CommentForm()
    if form.validate_on_submit():
        author = (form.author.data or "").strip()
        body = (form.body.data or "").strip()

        if len(author) > MAX_AUTHOR_LEN:
            flash("Nombre demasiado largo.", "error")
            return redirect(url_for("post_view", slug=slug))
        if len(body) > MAX_COMMENT_LEN:
            flash("Comentario demasiado largo.", "error")
            return redirect(url_for("post_view", slug=slug))

        db.session.add(Comment(post_id=post.id, author=author, body=body, is_approved=True))
        db.session.commit()
        flash("Comentario enviado (puede pasar a moderación).", "ok")
        return redirect(url_for("post_view", slug=slug))

    comments = db.session.scalars(
        select(Comment)
        .where(Comment.post_id == post.id)
        .where(Comment.is_approved.is_(True))
        .order_by(Comment.created_at.asc())
    ).all()

    return render_template(
        "post.html",
        post=post,
        comments=comments,
        form=form,
        **get_sidebar_context(),
    )


@app.route("/tag/<name>")
def tag_view(name: str):
    page = parse_page_arg()
    tag = db.session.scalar(select(Tag).where(Tag.name == name.lower()))
    if tag is None:
        abort(404)

    stmt = visible_posts_stmt().join(Post.tags).where(Tag.id == tag.id)
    posts, page, pages, total = paginate_posts(stmt, page=page, per_page=8)

    return render_template(
        "tag.html",
        tag=tag,
        posts=posts,
        page=page,
        pages=pages,
        total=total,
        **get_sidebar_context(),
    )


@app.route("/search")
def search():
    qstr = (request.args.get("q") or "").strip()
    page = parse_page_arg()

    stmt = visible_posts_stmt()
    if qstr:
        like = f"%{qstr}%"
        stmt = stmt.where(or_(Post.title.ilike(like), Post.content.ilike(like)))

    posts, page, pages, total = paginate_posts(stmt, page=page, per_page=8)

    return render_template(
        "search.html",
        q=qstr,
        posts=posts,
        page=page,
        pages=pages,
        total=total,
        **get_sidebar_context(),
    )


@app.route("/archive/<int:year>/<int:month>")
def archive(year: int, month: int):
    if month < 1 or month > 12:
        abort(404)

    page = parse_page_arg()
    start = datetime(year, month, 1)
    end = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

    stmt = visible_posts_stmt().where(Post.publish_at >= start).where(Post.publish_at < end)
    posts, page, pages, total = paginate_posts(stmt, page=page, per_page=8)

    return render_template(
        "archive.html",
        year=year,
        month=month,
        posts=posts,
        page=page,
        pages=pages,
        total=total,
        **get_sidebar_context(),
    )


@app.route("/feed.xml")
def feed():
    posts = db.session.scalars(visible_posts_stmt().order_by(Post.publish_at.desc()).limit(20)).all()
    site = request.host_url.rstrip("/")

    def esc(value: str | None) -> str:
        return (value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    items: list[str] = []
    for post in posts:
        link = f"{site}{url_for('post_view', slug=post.slug)}"
        items.append(
            f"""
        <item>
          <title>{esc(post.title)}</title>
          <link>{esc(link)}</link>
          <guid>{esc(link)}</guid>
          <pubDate>{post.publish_at.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
          <description>{esc(excerpt(post.content, 400))}</description>
        </item>
        """.strip()
        )

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Blog Médico - Demo</title>
    <link>{esc(site + url_for('index'))}</link>
    <description>Contenido educativo. No sustituye consulta médica.</description>
    <language>es</language>
    {''.join(items)}
  </channel>
</rss>
"""
    return Response(xml, content_type="application/rss+xml; charset=utf-8")


@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


# -----------------------------------------------------------------------------
# Auth / admin routes
# -----------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = (form.username.data or "").strip()
        password = form.password.data or ""
        user = db.session.scalar(select(User).where(User.username == username))
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            app.logger.info(
                "login_ok",
                extra={"event": "login_ok", "user": username, "ip": get_client_ip()},
            )
            flash("Login OK.", "ok")
            return redirect(url_for("admin_posts"))

        app.logger.warning(
            "login_fail",
            extra={"event": "login_fail", "user": username, "ip": get_client_ip()},
        )
        flash("Credenciales inválidas.", "error")
        return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = getattr(current_user, "username", "unknown")
    logout_user()
    app.logger.info("logout", extra={"event": "logout", "user": username})
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("index"))


@app.route("/admin")
@login_required
def admin_posts():
    posts = db.session.scalars(
        select(Post).where(Post.is_deleted.is_(False)).order_by(Post.created_at.desc())
    ).all()
    pending = db.session.scalar(
        select(func.count()).select_from(Comment).where(Comment.is_approved.is_(False))
    ) or 0
    return render_template("admin_posts.html", posts=posts, pending=pending)


@app.route("/admin/new", methods=["GET", "POST"])
@login_required
def admin_new_post():
    form = PostForm()
    if form.validate_on_submit():
        title = (form.title.data or "").strip()
        slug = simple_slugify(form.slug.data or title)
        content = (form.content.data or "").strip()
        status = form.status.data
        publish_at = form.publish_at.data or utcnow_naive()
        tag_names = parse_tags(form.tags.data)

        if len(title) > MAX_TITLE_LEN or len(slug) > MAX_SLUG_LEN or len(content) > MAX_POST_LEN:
            flash("Campos demasiado largos.", "error")
            return redirect(url_for("admin_new_post"))

        base_slug = slug
        i = 2
        while db.session.scalar(select(Post).where(Post.slug == slug)):
            slug = f"{base_slug}-{i}"
            i += 1

        post = Post(
            title=title,
            slug=slug,
            content=content,
            status=status,
            publish_at=publish_at,
            created_at=utcnow_naive(),
            updated_at=utcnow_naive(),
        )
        post.tags = upsert_tags(tag_names)
        db.session.add(post)
        db.session.commit()
        app.logger.info(
            "post_create",
            extra={"event": "post_create", "user": current_user.username, "slug": post.slug},
        )
        flash("Post creado.", "ok")
        return redirect(url_for("admin_posts"))

    return render_template("admin_edit.html", mode="new", form=form)


@app.route("/admin/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def admin_edit_post(post_id: int):
    post = db.get_or_404(Post, post_id)
    form = PostForm(obj=post)

    if request.method == "GET":
        form.slug.data = post.slug
        form.tags.data = ", ".join(tag.name for tag in post.tags)
        form.status.data = post.status
        form.publish_at.data = post.publish_at

    if form.validate_on_submit():
        title = (form.title.data or "").strip()
        slug = simple_slugify(form.slug.data or title)
        content = (form.content.data or "").strip()
        status = form.status.data
        publish_at = form.publish_at.data or utcnow_naive()
        tag_names = parse_tags(form.tags.data)

        if len(title) > MAX_TITLE_LEN or len(slug) > MAX_SLUG_LEN or len(content) > MAX_POST_LEN:
            flash("Campos demasiado largos.", "error")
            return redirect(url_for("admin_edit_post", post_id=post.id))

        existing = db.session.scalar(select(Post).where(Post.slug == slug))
        if existing and existing.id != post.id:
            flash("Ese slug ya existe.", "error")
            return redirect(url_for("admin_edit_post", post_id=post.id))

        post.title = title
        post.slug = slug
        post.content = content
        post.status = status
        post.publish_at = publish_at
        post.updated_at = utcnow_naive()
        post.tags = upsert_tags(tag_names)
        db.session.commit()
        app.logger.info(
            "post_edit",
            extra={
                "event": "post_edit",
                "user": current_user.username,
                "post_id": post.id,
                "slug": post.slug,
            },
        )
        flash("Post actualizado.", "ok")
        return redirect(url_for("admin_posts"))

    return render_template("admin_edit.html", mode="edit", form=form)


@app.route("/admin/delete/<int:post_id>", methods=["POST"])
@login_required
def admin_delete_post(post_id: int):
    post = db.get_or_404(Post, post_id)
    post.is_deleted = True
    post.updated_at = utcnow_naive()
    db.session.commit()
    app.logger.warning(
        "post_delete_soft",
        extra={
            "event": "post_delete_soft",
            "user": current_user.username,
            "post_id": post.id,
            "slug": post.slug,
        },
    )
    flash("Post eliminado (soft delete).", "ok")
    return redirect(url_for("admin_posts"))


@app.route("/admin/comments", methods=["GET", "POST"])
@login_required
def admin_comments():
    form = ModerateCommentForm()
    if form.validate_on_submit():
        try:
            comment_id = int(form.comment_id.data)
        except (TypeError, ValueError):
            flash("Comentario inválido.", "error")
            return redirect(url_for("admin_comments"))

        action = (form.action.data or "").strip().lower()
        if action not in {"approve", "reject", "delete"}:
            flash("Acción inválida.", "error")
            return redirect(url_for("admin_comments"))

        comment = db.get_or_404(Comment, comment_id)
        if action == "approve":
            comment.is_approved = True
        elif action == "reject":
            comment.is_approved = False
        else:
            db.session.delete(comment)

        db.session.commit()
        app.logger.info(
            "comment_moderation",
            extra={
                "event": "comment_moderation",
                "user": current_user.username,
                "action": action,
                "comment_id": comment_id,
            },
        )
        flash("Moderación aplicada.", "ok")
        return redirect(url_for("admin_comments"))

    pending = db.session.scalars(
        select(Comment)
        .where(Comment.is_approved.is_(False))
        .order_by(Comment.created_at.desc())
        .limit(200)
    ).all()
    recent = db.session.scalars(
        select(Comment)
        .where(Comment.is_approved.is_(True))
        .order_by(Comment.created_at.desc())
        .limit(50)
    ).all()
    return render_template("admin_comments.html", pending=pending, recent=recent, form=form)


# -----------------------------------------------------------------------------
# Error handlers
# -----------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="No encontrado."), 404


@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="Request demasiado grande."), 413

@app.route("/test-error-500")
def test_error_500():
    # This triggers a ZeroDivisionError
    app.logger.info("Triggering an intentional 500 error for Better Stack test.")
    result = 1 / 0
    return "This will never be seen"

@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    app.logger.exception(
        "unhandled_exception",
        extra={"event": "unhandled_exception", "path": request.path},
    )
    return render_template("error.html", code=500, message="Error interno."), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)

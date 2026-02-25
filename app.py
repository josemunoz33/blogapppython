import os
import random
import sys
import logging
import json
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, url_for, flash, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from forms import LoginForm, PostForm, CommentForm, ModerateCommentForm


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "module": record.module,
            "message": record.getMessage(),
        }
        for key in ("event","method","path","status_code","ip","ua","user","action","comment_id","post_id","slug"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


app = Flask(__name__)

# --- Logging setup (stdout + optional file) ---
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "json").lower()  # json|text

def _make_formatter():
    if LOG_FORMAT == "json":
        return JsonFormatter()
    return logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setLevel(LOG_LEVEL)
stream_handler.setFormatter(_make_formatter())

app.logger.setLevel(LOG_LEVEL)
app.logger.handlers = []
app.logger.addHandler(stream_handler)

if os.environ.get("ENABLE_FILE_LOG", "false").lower() == "true":
    os.makedirs("/data/logs", exist_ok=True)
    file_handler = RotatingFileHandler("/data/logs/app.log", maxBytes=2_000_000, backupCount=3)
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(_make_formatter())
    app.logger.addHandler(file_handler)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:////data/blog.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# DoS suave: evita requests enormes
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1MB

# Cookies hardening (mejor detrás de HTTPS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# app.config["SESSION_COOKIE_SECURE"] = True  # activar si usas HTTPS

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

post_tags = db.Table(
    "post_tags",
    db.Column("post_id", db.Integer, db.ForeignKey("post.id"), primary_key=True),
    db.Column("tag_id", db.Integer, db.ForeignKey("tag.id"), primary_key=True),
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def get_id(self): return str(self.id)
    @property
    def is_authenticated(self): return True
    @property
    def is_active(self): return True
    @property
    def is_anonymous(self): return False

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False, index=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    slug = db.Column(db.String(220), unique=True, nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)

    status = db.Column(db.String(20), default="published")  # draft|published
    publish_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    views = db.Column(db.Integer, default=0)

    tags = db.relationship("Tag", secondary=post_tags, lazy="subquery",
                           backref=db.backref("posts", lazy=True))
    comments = db.relationship("Comment", backref="post", cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    author = db.Column(db.String(120), nullable=False)
    body = db.Column(db.Text, nullable=False)
    is_approved = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

MAX_AUTHOR_LEN = 60
MAX_COMMENT_LEN = 1000
MAX_TITLE_LEN = 180
MAX_SLUG_LEN = 220
MAX_POST_LEN = 30000

def now_utc():
    return datetime.utcnow()

def simple_slugify(s):
    s = (s or "").strip().lower()
    out = []
    for ch in s:
        if ch.isalnum():
            out.append(ch)
        elif ch in [" ", "-", "_"]:
            out.append("-")
    slug = "".join(out)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "post"

def excerpt(text, n=240):
    text = (text or "").strip()
    return text if len(text) <= n else (text[:n].rstrip() + "...")

def parse_tags(tag_str):
    raw = (tag_str or "").split(",")
    out = []
    for t in raw:
        t = t.strip().lower()
        if t:
            out.append(t[:40])
    seen, uniq = set(), []
    for t in out:
        if t not in seen:
            uniq.append(t)
            seen.add(t)
    return uniq[:12]

def upsert_tags(tag_names):
    tags = []
    for name in tag_names:
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(name=name)
            db.session.add(tag)
        tags.append(tag)
    return tags

def visible_post_query():
    return (Post.query
            .filter(Post.is_deleted == False)
            .filter(Post.status == "published")
            .filter(Post.publish_at <= now_utc()))

def paginate(query, page, per_page=8):
    total = query.count()
    pages = max((total + per_page - 1) // per_page, 1)
    page = max(min(page, pages), 1)
    items = (query.order_by(Post.publish_at.desc())
             .limit(per_page)
             .offset((page - 1) * per_page)
             .all())
    return items, page, pages, total

app.jinja_env.globals.update(excerpt=excerpt)

@app.before_request
def log_request_info():
    app.logger.info(
        "request",
        extra={
            "event": "request",
            "method": request.method,
            "path": request.path,
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
            "ua": (request.headers.get("User-Agent", "-") or "-")[:120],
        },
    )

@app.after_request
def log_response_info(response):
    app.logger.info(
        "response",
        extra={
            "event": "response",
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        },
    )
    return response

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.cli.command("initdb")
def initdb():
    os.makedirs("/data", exist_ok=True)
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        u = User(username="admin", password_hash=generate_password_hash(pw))
        db.session.add(u)
        db.session.commit()
        print("Created admin user: admin")
        print("Admin password:", pw)

TOPICS = [
    "prevención", "nutrición", "salud mental", "cardiología", "diabetes",
    "dermatología", "pediatría", "ejercicio", "sueño", "vacunas",
    "primeros auxilios", "salud pública", "hipertensión", "hábitos"
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
    "Recuerda el contexto: edad, antecedentes familiares, sueño, estrés, actividad y alimentación afectan el resultado."
]
LISTS = [
    ["Hidrátate de forma regular (sin extremos).","Incluye proteína en comidas principales.","Camina 20–30 min, 4–5 días/semana.","Evita “todo o nada”: apunta a constancia.","Haz chequeos si tienes antecedentes familiares."],
    ["Rutina de sueño consistente (hora fija).","Luz solar en la mañana 10–15 min.","Pantallas fuera 60 min antes de dormir.","Cafeína solo temprano.","Cuarto fresco y oscuro."],
    ["Aprende a leer etiquetas simples.","Aumenta fibra (frutas, vegetales, legumbres).","Reduce ultraprocesados gradualmente.","No ‘demonices’ grupos enteros de alimentos.","Planifica snacks sencillos (yogurt, fruta, nueces)."],
]

def make_post_body():
    parts = []
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
    parts.append("Si quieres, lleva un registro (presión, sueño, pasos, glucosa si aplica) y revisa tendencias. Lo importante es el progreso, no la perfección.")
    return "\n".join(parts)

@app.cli.command("seed")
def seed():
    os.makedirs("/data", exist_ok=True)
    db.create_all()
    if Post.query.count() > 8:
        print("Seed skipped (already has data).")
        return

    for i in range(18):
        title = TITLES[i % len(TITLES)]
        slug = simple_slugify(title)
        base = slug
        n = 2
        while Post.query.filter_by(slug=slug).first():
            slug = f"{base}-{n}"
            n += 1

        status = "published" if i % 6 != 0 else "draft"
        publish_at = now_utc() - timedelta(days=random.randint(0, 150))
        if i in (2, 11):
            publish_at = now_utc() + timedelta(days=random.randint(2, 12))  # scheduled

        p = Post(title=title, slug=slug, content=make_post_body(),
                 status=status, publish_at=publish_at,
                 created_at=publish_at, updated_at=publish_at)
        p.tags = upsert_tags(random.sample(TOPICS, k=random.randint(2, 4)))
        db.session.add(p)
        db.session.flush()

        for _ in range(random.randint(0, 5)):
            c = Comment(post_id=p.id,
                        author=random.choice(["Paciente", "Visitante", "Ana", "Luis", "ClínicaXYZ", "Admin"]),
                        body="Gracias por el artículo. Muy claro. ¿Recomiendas algún recurso adicional para profundizar?",
                        is_approved=(random.randint(0, 10) != 0))
            db.session.add(c)

    db.session.commit()
    print("Seeded medical posts, tags and comments.")

@app.route("/")
def index():
    page = request.args.get("page", "1")
    try: page = int(page)
    except ValueError: page = 1

    q = visible_post_query()
    posts, page, pages, total = paginate(q, page, per_page=8)

    latest = visible_post_query().limit(6).all()
    tag_cloud = Tag.query.order_by(Tag.name.asc()).limit(24).all()

    # archive links (last 6 months)
    months = []
    today = now_utc().replace(day=1)
    cur = today
    for _ in range(6):
        y, m = cur.year, cur.month
        months.append((y, m))
        cur = (cur - timedelta(days=1)).replace(day=1)

    return render_template("index.html", posts=posts, page=page, pages=pages, total=total,
                           latest=latest, tag_cloud=tag_cloud, months=months)

@app.route("/p/<slug>", methods=["GET", "POST"])
def post_view(slug):
    post = visible_post_query().filter(Post.slug == slug).first_or_404()

    post.views = (post.views or 0) + 1
    post.updated_at = now_utc()
    db.session.commit()

    form = CommentForm()
    if form.validate_on_submit():
        author = form.author.data.strip()
        body = form.body.data.strip()

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

    comments = (Comment.query
                .filter_by(post_id=post.id, is_approved=True)
                .order_by(Comment.created_at.asc()).all())

    latest = visible_post_query().limit(6).all()
    tag_cloud = Tag.query.order_by(Tag.name.asc()).limit(24).all()

    return render_template("post.html", post=post, comments=comments, latest=latest, tag_cloud=tag_cloud, form=form)

@app.route("/tag/<name>")
def tag_view(name):
    page = request.args.get("page", "1")
    try: page = int(page)
    except ValueError: page = 1

    tag = Tag.query.filter_by(name=name.lower()).first_or_404()
    q = (visible_post_query().join(post_tags).join(Tag).filter(Tag.id == tag.id))
    posts, page, pages, total = paginate(q, page, per_page=8)

    latest = visible_post_query().limit(6).all()
    tag_cloud = Tag.query.order_by(Tag.name.asc()).limit(24).all()

    return render_template("tag.html", tag=tag, posts=posts, page=page, pages=pages, total=total,
                           latest=latest, tag_cloud=tag_cloud)

@app.route("/search")
def search():
    qstr = (request.args.get("q") or "").strip()
    page = request.args.get("page", "1")
    try: page = int(page)
    except ValueError: page = 1

    q = visible_post_query()
    if qstr:
        like = f"%{qstr}%"
        q = q.filter((Post.title.like(like)) | (Post.content.like(like)))

    posts, page, pages, total = paginate(q, page, per_page=8)
    latest = visible_post_query().limit(6).all()
    tag_cloud = Tag.query.order_by(Tag.name.asc()).limit(24).all()

    return render_template("search.html", q=qstr, posts=posts, page=page, pages=pages, total=total,
                           latest=latest, tag_cloud=tag_cloud)

@app.route("/archive/<int:year>/<int:month>")
def archive(year, month):
    page = request.args.get("page", "1")
    try: page = int(page)
    except ValueError: page = 1

    start = datetime(year, month, 1)
    end = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)

    q = visible_post_query().filter(Post.publish_at >= start).filter(Post.publish_at < end)
    posts, page, pages, total = paginate(q, page, per_page=8)

    latest = visible_post_query().limit(6).all()
    tag_cloud = Tag.query.order_by(Tag.name.asc()).limit(24).all()

    return render_template("archive.html", year=year, month=month, posts=posts, page=page, pages=pages, total=total,
                           latest=latest, tag_cloud=tag_cloud)

@app.route("/feed.xml")
def feed():
    posts = visible_post_query().order_by(Post.publish_at.desc()).limit(20).all()
    site = request.host_url.rstrip("/")

    def esc(s):
        return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    items = []
    for p in posts:
        link = f"{site}{url_for('post_view', slug=p.slug)}"
        items.append(f"""
        <item>
          <title>{esc(p.title)}</title>
          <link>{esc(link)}</link>
          <guid>{esc(link)}</guid>
          <pubDate>{p.publish_at.strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
          <description>{esc(excerpt(p.content, 400))}</description>
        </item>
        """.strip())

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
    return Response(xml, mimetype="application/rss+xml; charset=utf-8")

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data or ""
        u = User.query.filter_by(username=username).first()
        if u and check_password_hash(u.password_hash, password):
            login_user(u)
            app.logger.info("login_ok", extra={"event":"login_ok","user":username,"ip":request.headers.get("X-Forwarded-For", request.remote_addr)})
            flash("Login OK.", "ok")
            return redirect(url_for("admin_posts"))
        app.logger.warning("login_fail", extra={"event":"login_fail","user":username,"ip":request.headers.get("X-Forwarded-For", request.remote_addr)})
        flash("Credenciales inválidas.", "error")
        return redirect(url_for("login"))
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    app.logger.info("logout", extra={"event":"logout","user":getattr(current_user, "username", "unknown")})
    logout_user()
    flash("Sesión cerrada.", "ok")
    return redirect(url_for("index"))

@app.route("/admin")
@login_required
def admin_posts():
    posts = Post.query.filter(Post.is_deleted == False).order_by(Post.created_at.desc()).all()
    pending = Comment.query.filter_by(is_approved=False).count()
    return render_template("admin_posts.html", posts=posts, pending=pending)

@app.route("/admin/new", methods=["GET", "POST"])
@login_required
def admin_new_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.title.data.strip()
        slug = simple_slugify(form.slug.data or title)
        content = form.content.data.strip()
        status = form.status.data
        publish_at = form.publish_at.data or now_utc()
        tags = parse_tags(form.tags.data)

        if len(title) > MAX_TITLE_LEN or len(slug) > MAX_SLUG_LEN or len(content) > MAX_POST_LEN:
            flash("Campos demasiado largos.", "error")
            return redirect(url_for("admin_new_post"))

        base = slug
        i = 2
        while Post.query.filter_by(slug=slug).first():
            slug = f"{base}-{i}"
            i += 1

        p = Post(title=title, slug=slug, content=content, status=status, publish_at=publish_at,
                 created_at=now_utc(), updated_at=now_utc())
        p.tags = upsert_tags(tags)
        db.session.add(p)
        db.session.commit()
        app.logger.info("post_create", extra={"event":"post_create","user":current_user.username,"slug":p.slug})
        flash("Post creado.", "ok")
        return redirect(url_for("admin_posts"))
    return render_template("admin_edit.html", mode="new", form=form)

@app.route("/admin/edit/<int:post_id>", methods=["GET", "POST"])
@login_required
def admin_edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostForm(obj=post)

    if request.method == "GET":
        form.slug.data = post.slug
        form.tags.data = ", ".join([t.name for t in post.tags])
        form.status.data = post.status
        form.publish_at.data = post.publish_at

    if form.validate_on_submit():
        title = form.title.data.strip()
        slug = simple_slugify(form.slug.data or title)
        content = form.content.data.strip()
        status = form.status.data
        publish_at = form.publish_at.data or now_utc()
        tags = parse_tags(form.tags.data)

        if len(title) > MAX_TITLE_LEN or len(slug) > MAX_SLUG_LEN or len(content) > MAX_POST_LEN:
            flash("Campos demasiado largos.", "error")
            return redirect(url_for("admin_edit_post", post_id=post.id))

        existing = Post.query.filter_by(slug=slug).first()
        if existing and existing.id != post.id:
            flash("Ese slug ya existe.", "error")
            return redirect(url_for("admin_edit_post", post_id=post.id))

        post.title = title
        post.slug = slug
        post.content = content
        post.status = status
        post.publish_at = publish_at
        post.updated_at = now_utc()
        post.tags = upsert_tags(tags)
        db.session.commit()
        app.logger.info("post_edit", extra={"event":"post_edit","user":current_user.username,"post_id":post.id,"slug":post.slug})

        flash("Post actualizado.", "ok")
        return redirect(url_for("admin_posts"))

    return render_template("admin_edit.html", mode="edit", form=form)

@app.route("/admin/delete/<int:post_id>", methods=["POST"])
@login_required
def admin_delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.is_deleted = True
    post.updated_at = now_utc()
    db.session.commit()
    app.logger.warning("post_delete_soft", extra={"event":"post_delete_soft","user":current_user.username,"post_id":post.id,"slug":post.slug})
    flash("Post eliminado (soft delete).", "ok")
    return redirect(url_for("admin_posts"))

@app.route("/admin/comments", methods=["GET", "POST"])
@login_required
def admin_comments():
    form = ModerateCommentForm()
    if form.validate_on_submit():
        cid = int(form.comment_id.data)
        action = form.action.data
        c = Comment.query.get_or_404(cid)

        if action == "approve":
            c.is_approved = True
        elif action == "reject":
            c.is_approved = False
        elif action == "delete":
            db.session.delete(c)

        db.session.commit()
        app.logger.info("comment_moderation", extra={"event":"comment_moderation","user":current_user.username,"action":action,"comment_id":cid})
        flash("Moderación aplicada.", "ok")
        return redirect(url_for("admin_comments"))

    pending = Comment.query.filter_by(is_approved=False).order_by(Comment.created_at.desc()).limit(200).all()
    recent = Comment.query.filter_by(is_approved=True).order_by(Comment.created_at.desc()).limit(50).all()
    return render_template("admin_comments.html", pending=pending, recent=recent, form=form)

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="No encontrado."), 404

@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", code=413, message="Request demasiado grande."), 413

@app.route("/test-error-500")
def test_error_500():
    # This triggers a ZeroDivisionError
    app.logger.info("Triggering an intentional 500 error for Better Stack test.")
    result = 1 / 0
    return "This will never be seen"

@app.errorhandler(Exception)
def handle_unexpected_error(e):
    app.logger.exception("unhandled_exception", extra={"event":"unhandled_exception","path":request.path})
    return render_template("error.html", code=500, message="Error interno."), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)




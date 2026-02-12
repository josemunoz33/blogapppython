from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, DateTimeField, HiddenField
from wtforms.validators import DataRequired, Length, Optional

class SearchForm(FlaskForm):
    q = StringField("Buscar", validators=[Optional(), Length(max=120)])

class LoginForm(FlaskForm):
    username = StringField("Usuario", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Contraseña", validators=[DataRequired(), Length(max=128)])

class CommentForm(FlaskForm):
    author = StringField("Nombre", validators=[DataRequired(), Length(max=60)])
    body = TextAreaField("Comentario", validators=[DataRequired(), Length(max=1000)])

class PostForm(FlaskForm):
    title = StringField("Título", validators=[DataRequired(), Length(max=180)])
    slug = StringField("Slug (opcional)", validators=[Optional(), Length(max=220)])
    tags = StringField("Tags (coma-separados)", validators=[Optional(), Length(max=200)])
    status = SelectField("Estado", choices=[("draft", "Draft"), ("published", "Published")], default="published")
    publish_at = DateTimeField("Publicar en (UTC) - opcional", validators=[Optional()], format="%Y-%m-%d %H:%M:%S")
    content = TextAreaField("Contenido", validators=[DataRequired(), Length(max=30000)])

class ModerateCommentForm(FlaskForm):
    comment_id = HiddenField(validators=[DataRequired()])
    action = HiddenField(validators=[DataRequired()])

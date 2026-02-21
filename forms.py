from flask_wtf import FlaskForm
from wtforms import DateTimeField, HiddenField, PasswordField, SelectField, StringField, TextAreaField
from wtforms.validators import AnyOf, DataRequired, Length, Optional


def _strip(value: str | None):
    if isinstance(value, str):
        return value.strip()
    return value


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=3, max=80)],
        filters=[_strip],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=3, max=255)],
    )


class PostForm(FlaskForm):
    title = StringField(
        "Title",
        validators=[DataRequired(), Length(min=3, max=180)],
        filters=[_strip],
    )
    slug = StringField(
        "Slug",
        validators=[Optional(), Length(max=220)],
        filters=[_strip],
    )
    tags = StringField(
        "Tags",
        validators=[Optional(), Length(max=400)],
        filters=[_strip],
    )
    status = SelectField(
        "Status",
        choices=[("draft", "draft"), ("published", "published")],
        validators=[DataRequired()],
    )
    publish_at = DateTimeField(
        "Publish At",
        format="%Y-%m-%d %H:%M:%S",
        validators=[Optional()],
    )
    content = TextAreaField(
        "Content",
        validators=[DataRequired(), Length(min=10, max=30000)],
        filters=[_strip],
    )


class CommentForm(FlaskForm):
    author = StringField(
        "Nombre",
        validators=[DataRequired(), Length(min=2, max=60)],
        filters=[_strip],
    )
    body = TextAreaField(
        "Comentario",
        validators=[DataRequired(), Length(min=3, max=1000)],
        filters=[_strip],
    )


class ModerateCommentForm(FlaskForm):
    comment_id = HiddenField(validators=[DataRequired()])
    action = HiddenField(
        validators=[DataRequired(), AnyOf(["approve", "reject", "delete"])]
    )

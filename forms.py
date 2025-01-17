from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Post")


# Create a form to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Register")


# Create a form to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# Create a form to add comments
class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment down here (please be respectful)", validators=[DataRequired()])
    submit = SubmitField("Comment")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired()])
    confirm_new_password = PasswordField("Confirm New Password", validators=[DataRequired()])
    submit = SubmitField("Change Password")


class SearchForm(FlaskForm):
    searched = StringField("Searched", validators=[DataRequired()])
    submit = SubmitField("Search")


class ChangeEmailForm(FlaskForm):
    new_email = StringField("Email", validators=[DataRequired()])
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    submit = SubmitField("Change Email")


class ChangeUsernameForm(FlaskForm):
    new_username = StringField("Username", validators=[DataRequired()])
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    submit = SubmitField("Change Username")


class SuggestPostForm(FlaskForm):
    title = StringField("What should the title be?", validators=[DataRequired()])
    reason = StringField("Reason for Suggestion", validators=[DataRequired()])
    body = CKEditorField("Suggest Post Content (You can add suitable images too)", validators=[DataRequired()])
    submit = SubmitField("Suggest")

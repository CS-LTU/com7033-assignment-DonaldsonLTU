# forms.py
# I'm defining my login form here so validation is clean and testable.

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

class LoginForm(FlaskForm):
    # I'm validating username: required, 3–30 chars, letters/numbers/underscore only.
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Please enter your username."),
            Length(min=3, max=30, message="Username must be 3–30 characters."),
            Regexp(r"^[A-Za-z0-9_]+$", message="Only letters, numbers, and underscore.")
        ]
    )
    # I am validating password length so we don't accept short and weak ones.
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Please enter your password."),
            Length(min=6, message="Password should be at least 6 characters.")
        ]
    )
    submit = SubmitField("Sign in")
# forms.py
# I'm defining my login form here so validation is clean and testable.

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, FloatField
from wtforms.validators import DataRequired, Length, Regexp, Optional, NumberRange, EqualTo

# --- LOGIN FORM (already existing) ---
class LoginForm(FlaskForm):
    # I'm validating username: required, 3–30 chars, letters/numbers/underscore/hyphen.
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Please enter your username."),
            Length(min=3, max=30, message="Username must be 3–30 characters."),
            # I’m allowing letters, numbers, underscore, and hyphen so 'patient-1665' is valid
            Regexp(r"^[A-Za-z0-9_-]+$", message="Only letters, numbers, underscore, and hyphen.")
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

# --- ADMIN FORMS FOR MANAGING PATIENT RECORDS AND PASSWORDS ---
class PatientForm(FlaskForm):
    # I'm matching the dataset columns (id is unique in dataset)
    id = IntegerField("ID", validators=[DataRequired()])
    gender = StringField("Gender", validators=[DataRequired(), Length(max=20)])
    age = FloatField("Age", validators=[DataRequired(), NumberRange(min=0)])
    hypertension = IntegerField("Hypertension (0/1)", validators=[DataRequired(), NumberRange(min=0, max=1)])
    heart_disease = IntegerField("Heart disease (0/1)", validators=[DataRequired(), NumberRange(min=0, max=1)])
    ever_married = StringField("Ever married", validators=[DataRequired(), Length(max=10)])
    work_type = StringField("Work type", validators=[DataRequired(), Length(max=30)])
    residence_type = StringField("Residence type", validators=[DataRequired(), Length(max=10)])
    avg_glucose_level = FloatField("Avg glucose level", validators=[DataRequired(), NumberRange(min=0)])
    bmi = FloatField("BMI", validators=[Optional()])
    smoking_status = StringField("Smoking status", validators=[Optional(), Length(max=30)])
    stroke = IntegerField("Stroke (0/1)", validators=[DataRequired(), NumberRange(min=0, max=1)])
    submit = SubmitField("Save")

class DeleteForm(FlaskForm):
    id = IntegerField("ID", validators=[DataRequired()])
    submit = SubmitField("Delete")

class EditLookupForm(FlaskForm):
    id = IntegerField("ID", validators=[DataRequired()])
    submit = SubmitField("Find")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm new password",
                                     validators=[DataRequired(), EqualTo('new_password', message="Passwords must match.")])
    submit = SubmitField("Change password")
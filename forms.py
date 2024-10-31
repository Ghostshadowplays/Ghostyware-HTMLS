from functools import wraps
from flask import render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, BooleanField, SubmitField, HiddenField, FileField, TextAreaField
from wtforms.validators import DataRequired, Email, InputRequired, Optional, EqualTo


class AcceptFriendRequestForm(FlaskForm):
    csrf_token = HiddenField()

class FriendRequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Send Friend Request')

class ProfileForm(FlaskForm):
    profile_photo = FileField('Profile Photo', validators=[Optional()])  # Optional if you want to allow bio updates without a photo
    bio = TextAreaField('Bio', validators=[DataRequired()])  # Ensure bio is required
    submit = SubmitField('Update Profile')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Register')
    is_admin = BooleanField('Register as is_admin')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ChangePasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Submit')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class FeedbackForm(FlaskForm):
    username = HiddenField('Username')  # Assuming this is pre-filled or hidden
    message = StringField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit Feedback')

class ForgotPasswordForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Password Reset')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match.')])
    submit = SubmitField('Reset Password')

class ChangeEmailForm(FlaskForm):
    new_email = EmailField('New Email', validators=[DataRequired(), Email()])
    confirm_email = EmailField('Confirm New Email', validators=[DataRequired(), EqualTo('new_email', message='Emails must match.')])
    submit = SubmitField('Change Email')

class ResendConfirmationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Resend Confirmation Email')
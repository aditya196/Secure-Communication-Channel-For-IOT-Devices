import re
from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField,SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, InputRequired
from flask_wtf.file import FileField, FileAllowed
from iot_security.models import User, City


class SignupForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    email = StringField('Email', validators=[Email()])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    terms_and_conditions = BooleanField(
        'I agree to the Security terms and conditions', validators=[DataRequired()])
    
    aadhar_number = StringField('Aadhar Number', validators=[
                               DataRequired(), Length(min=12, max=12)])

    submit = SubmitField('Signup')
    def validate_username(self, username):
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = User.query.filter_by(username=username.data.lower()).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_email(self, email):
        org = User.query.filter_by(email=email.data.lower()).first()
        if org:
            raise ValidationError('Email is aleady in use.')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')
    
    def validate_aadhar_number(self, aadhar_number):
        if not aadhar_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    submit = SubmitField('Login')



class ResendEmailConfirmationForm(FlaskForm):
    email = StringField(
        'Enter Email Address', validators=[DataRequired()])
    submit = SubmitField('Resend Email Confirmation')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(
        'Enter Email Address', validators=[DataRequired()])
    submit = SubmitField('Reset Password')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Update new password')


class LoginWithEmailForm(FlaskForm):
    email = StringField(
        'Enter Email Address', validators=[DataRequired()])
    submit = SubmitField('Login')

class ValidateotpForm(FlaskForm):
    otp = StringField(
        'Enter OTP', validators=[DataRequired()])
    submit = SubmitField('Verify')


class ResendValidateotpForm(FlaskForm):
    phone = StringField(
        'Enter Phone Number', validators=[DataRequired()])
    submit = SubmitField('Submit')
    
    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')


class AddPropertyForm(FlaskForm):
    house_number = StringField('Enter house Number:', validators=[DataRequired()])
    building_name = StringField('Enter building name:', validators=[DataRequired()])
    street_name = StringField('Enter street name:', validators=[DataRequired()])
    state = SelectField('state')
    city = SelectField('city', choices=[])
    pincode = StringField('Enter pincode:', validators=[DataRequired()])
    submit = SubmitField('Submit')

    def __init__(self):
        super(AddPropertyForm, self).__init__()
        self.state.choices = [(i.state, i.state) for i in City.query.distinct(City.state).all()]

class AddTenantCheck(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    submit = SubmitField('Submit')

    def validate_username(self, username):
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = User.query.filter_by(username=username.data).first()
        if org is None:
            raise ValidationError('Username not registered. Please check the entered username')
        elif org.id == current_user.id:
            raise ValidationError('Invalid Input. Cannot make owner a tenant.')
    
    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')
        
        org = User.query.filter_by(phone_number=phone_number.data).first()
        if org is None:
            raise ValidationError('Phone Number not registered. Please check the entered phone number')    
        elif org.id == current_user.id:
            raise ValidationError('Invalid Input. Cannot make owner a tenant.')



class SupportQueryForm(FlaskForm):
    prob_text = TextAreaField('Enter You Problem', render_kw={"rows": 15, "cols": 20},validators=[DataRequired()])
    prob_type = SelectField('Property Type' , choices=[('Meter', 'Meter - Problem'), ('Billing', 'Billing - Problem'), ('deactivate', 'Deactivation'), ('other', 'Other')],validators=[InputRequired()])
    submit = SubmitField('Submit')
    
'''

class ProfileUpdateForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    current_password = PasswordField('Current Password', validators=[
        Optional()
    ])
    password = PasswordField('Password', validators=[
                             Optional(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
        EqualTo('password')])

    submit = SubmitField('Update')

    def validate_current_password(self, current_password):
        if not current_user.check_password(current_password.data):
            raise ValidationError('Incorrect password')

'''
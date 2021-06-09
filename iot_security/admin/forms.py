import re
from flask_wtf import FlaskForm, RecaptchaField
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, RadioField, SelectField, FloatField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional, InputRequired
from flask_wtf.file import FileField, FileAllowed
from iot_security.models import Admin, Iotserver, Iotdevice, Slablog


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    employee_id = StringField('EmployeeID', validators=[
                               DataRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[Email()])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')
    def validate_username(self, username):
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = Admin.query.filter_by(username=username.data).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_employee_id(self, employee_id):
        org = Admin.query.filter_by(employee_id=employee_id.data).first()
        if org:
            raise ValidationError('EmployeeID aleady exists.')

    def validate_email(self, email):
        org = Admin.query.filter_by(email=email.data.lower()).first()
        if org:
            raise ValidationError('Email is aleady in use.')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
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


class ServerRegistrationForm(FlaskForm):
    server_reg_name = StringField('Server Registration Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    pincode = StringField('Pincode', validators=[
                               DataRequired(), Length(min=3, max=10)])
    submit = SubmitField('Signup')
    

class DeviceRegistrationForm(FlaskForm):
    device_reg_name = StringField('Device Registration Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    
    address = StringField('Address', validators=[
                           DataRequired(), Length(min=2, max=255)])
    
    prop_type = SelectField('Property Type' , choices=[(True, 'Housing'), (False, 'Commercial')],validators=[InputRequired()],
    coerce=lambda x: x == 'True')
    submit = SubmitField('Signup')
        
        
class AssignDeviceServerForm(FlaskForm):
    server_id = SelectField('Server ID', coerce=int)
    device_id = SelectField('Device ID', coerce=int)
    submit = SubmitField('Register')

    def __init__(self):
        super(AssignDeviceServerForm, self).__init__()
        self.server_id.choices = [(i.id, i.server_reg_name) for i in Iotserver.query.filter_by(server_reg_confirm = True, is_active = True).all()]
        self.device_id.choices = [(i.id, i.device_reg_name) for i in Iotdevice.query.filter_by(device_reg_confirm = True, property_assigned_status = False).all()]



class UpdateUsernameForm(FlaskForm):
    old_username = StringField('Old Username', validators=[
                                DataRequired(), Length(min=1, max=10)])
    username = StringField('Username', validators=[
                                DataRequired(), Length(min=1, max=10)])
    submit = SubmitField('Register')


class UpdatePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[
                             DataRequired(), Length(min=6)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    submit = SubmitField('Register')


class UpdateEmailForm(FlaskForm):
    old_email = StringField('Old Email', validators=[Email()])
    email = StringField('Email', validators=[Email()])
    submit = SubmitField('Register')


class ActivateProduct(FlaskForm):
    activation_key = StringField('Activation Key', validators=[DataRequired(), Length(min=16, max=16)])
    submit = SubmitField('Submit')


class SuperUserRegister(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    employee_id = StringField('EmployeeID', validators=[
                               DataRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[Email()])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')
    def validate_username(self, username):
        if username == 'admin':
            raise ValidationError('This username is not permitted. Please choose another username')
        
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = Admin.query.filter_by(username=username.data).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_employee_id(self, employee_id):
        org = Admin.query.filter_by(employee_id=employee_id.data).first()
        if org:
            raise ValidationError('EmployeeID aleady exists.')

    def validate_password(self, password):
        if password == 'admin':
            raise ValidationError('This password is not permitted. Please choose another')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')


class AddAdminsForm(FlaskForm):
    employee_id = StringField('EmployeeID', validators=[
                               DataRequired(), Length(min=3, max=10)])
    email = StringField('Email', validators=[Email()])

    role = RadioField('Role', choices=[('super_user','Super User'),('admin','Admin')])
    
    submit = SubmitField('Submit')

    def validate_employee_id(self, employee_id):
        org = Admin.query.filter_by(employee_id=employee_id.data).first()
        if org:
            raise ValidationError('EmployeeID aleady exists.')

    def validate_email(self, email):
        org = Admin.query.filter_by(email=email.data.lower()).first()
        if org:
            raise ValidationError('Email is aleady in use.')


class NewAdminRegistrationForm(FlaskForm):
    name = StringField('Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=255)])
    phone_number = StringField('Phone number', validators=[
                               DataRequired(), Length(min=10, max=10)])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    password_confirm = PasswordField('Password Confirmation', validators=[
                                     DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')
    def validate_username(self, username):
        if username == 'admin':
            raise ValidationError('This username is not permitted. Please choose another username')
        
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', username.data.lower()):
            raise ValidationError('Please enter valid characters')

        org = Admin.query.filter_by(username=username.data).first()
        if org:
            raise ValidationError('Username is aleady in use.')

    def validate_password(self, password):
        if password == 'admin':
            raise ValidationError('This password is not permitted. Please choose another')

    def validate_phone_number(self, phone_number):
        if not phone_number.data.isdigit():
            raise ValidationError('Only numeric values are allowed')


class SetBillSlabCostForm(FlaskForm):
    low_slab = StringField('Lower Slab Limit', validators=[
        DataRequired(), Length(min=1, max=255)])
    high_slab = StringField('Higher Slab Limit', validators=[
        DataRequired(), Length(min=1, max=255)])
    housing_cost = FloatField('Housing Cost', validators=[
        DataRequired()])
    commercial_cost = FloatField('Commercial Cost', validators=[
        DataRequired()])
    penalty = StringField('Penalty Cost', validators=[
        DataRequired(), Length(min=1, max=255)])
    # ^[0-9]*$
    def validate_low_slab(self, low_slab):
        if not low_slab.data.isdigit():
            raise ValidationError('Only numeric values are allowed')
    
    def validate_high_slab(self, high_slab):
        print(high_slab.data)
        if not re.match('^MAX$', high_slab.data):
            if not high_slab.data.isdigit():
                raise ValidationError('Only numeric values are allowed or MAX')
    
    def validate_penalty(self, penalty):
        if not penalty.data.isdigit():
            raise ValidationError('Only numeric values are allowed')




class SetBillTaxForm(FlaskForm):
    tax_name = StringField('Tax Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    
    tax_rate = FloatField('Tax Rate', validators=[
                               DataRequired()])
    def validate_tax_name(self, tax_name):
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', tax_name.data.lower()):
            raise ValidationError('Please enter valid characters')


class SetMiscellaneousTaxForm(FlaskForm):
    tax_name = StringField('Miscellaneous Tax Name', validators=[
        DataRequired(), Length(min=2, max=255)])
    
    tax_amount = FloatField('Miscellaneous Tax Amount', validators=[
                               DataRequired()])
    def validate_tax_name(self, tax_name):
        if not re.match('^[A-Za-z]+(?:[-][A-Za-z0-9]+)*$', tax_name.data.lower()):
            raise ValidationError('Please enter valid characters')


class TaxEditForm(FlaskForm):
    tax_ammount = StringField('New Tax Amount', validators=[
                           DataRequired()])
    tax_rate = StringField('New Tax Rate', validators=[
                           DataRequired()])
    submit = SubmitField('Submit')


class AddStateCityForm(FlaskForm):
    city = StringField('City Name', validators=[
                                DataRequired(), Length(min=1, max=255)])
    
    
    
    
    
    
    
    
    
    
    
    
    
    # def validate(self):
    #     rv = FlaskForm.validate(self)
    #     if not rv:
    #         return False
    #     low_slab = self.low_slab.data
    #     high_slab = self.high_slab.data
    #     slab_in_range = Slablog.query.all()
    #     print(len(high_slab))
    #     if high_slab  != 'MAX':
    #         if int(low_slab) == int(high_slab) :
    #             self.low_slab.errors.append("Lower Slab cannot be equal to Upper Slab")
    #             return False
    #         if slab_in_range != []:
    #             for i in slab_in_range:
    #                 # -- Check if lower slab is higher than upper slab
    #                 if int(low_slab) >= int(high_slab):
    #                     self.low_slab.errors.append("Cannot Add Slab. As Lower slab is greater than the upper slab")                            
    #                     return False
    #                 # -- Check if lower slab or high slab is in a pre defined range
    #                 lower_limit = int(i.lower_slab)
    #                 if i.upper_slab != 'MAX':
    #                     upper_limit = int(i.upper_slab)
    #                     if int(low_slab) in range(lower_limit,upper_limit+1) or int(high_slab) in range(lower_limit,upper_limit+1):
    #                         self.low_slab.errors.append("Please Set the slab right. It cannot be between the sange of the previous slab")
    #                         self.high_slab.errors.append("Please Set the slab right. It cannot be between the sange of the previous slab")
    #                         return False
    #                 else:
    #                     continue
    #     # If the upper Limit is Max then just check the lower limit
    #     for i in slab_in_range:
    #         lower_limit = int(i.lower_slab)
    #         if i.upper_slab != 'MAX':
    #             upper_limit = int(i.upper_slab)
    #             if int(low_slab) in range(lower_limit,upper_limit+1):
    #                 self.low_slab.errors.append("Please Set the slab right. It cannot be between the sange of the previous slab")
    #                 return False
    #     return True
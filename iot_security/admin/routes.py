from functools import wraps
import requests
from secrets import token_urlsafe
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, current_user, login_required, logout_user
from iot_security.admin.forms import (RegistrationForm, LoginForm,
                                              ResendEmailConfirmationForm,
                                              ResetPasswordRequestForm,
                                              ResetPasswordForm,
                                              LoginWithEmailForm,
                                              ServerRegistrationForm,
                                              DeviceRegistrationForm,
                                              AssignDeviceServerForm,
                                              UpdateUsernameForm,
                                              UpdatePasswordForm,
                                              UpdateEmailForm,
                                              ActivateProduct,
                                              SuperUserRegister,
                                              AddAdminsForm,
                                              NewAdminRegistrationForm,
                                              SetBillSlabCostForm,
                                              SetBillTaxForm,
                                              SetMiscellaneousTaxForm,
                                              AddStateCityForm)
from iot_security.models import (Admin , 
                                AdminToken, 
                                User, 
                                UserToken, 
                                Iotserver, 
                                Iotdevice, 
                                Productactivation, 
                                Property, 
                                Slablog, 
                                Tax, 
                                Metertransactionlog, 
                                City, 
                                Miscellaneous,
                                Supportquery,
                                Billrequestdefaulters)
from iot_security.auth.billing import *
from iot_security.auth.utils import *
from iot_security import db
import base64
from base64 import b64encode
from base64 import b64decode
from iot_security import limiter
from requests.exceptions import HTTPError
from iot_security.admin.utils import (send_confirmation_mail,
                                        send_reset_password_mail,
                                        send_userapproval_mail,
                                        send_userreject_mail,
                                        send_login_email_mail,
                                        send_registration_mail,
                                        send_key_activation_mail,
                                        key_activated,
                                        key_created,
                                        super_user,
                                        key_not_activated,
                                        no_admin,
                                        send_support_query_completed_mail,
                                        send_support_query_pending_mail,
                                        remove_duplicate_iot_server)

admin = Blueprint('admin', __name__)



@admin.route('/' , methods=['GET','POST'])
@limiter.exempt
def activate():
    org = Productactivation.query.filter_by().first()
    if org is None or org == []:
        activation_key = Productactivation.generate_key()
        mail_id = 'authelectric@gmail.com'
        send_key_activation_mail(mail_id,activation_key)
    wrong_key = Productactivation.query.filter_by(activated = False).first()
    if wrong_key is None or wrong_key == []:
        active = True
        return render_template('admin/activate.html', item = active)
    else:
        active = False
        return render_template('admin/activate.html', item = active)



#Registraton of admin
@admin.route('/registration', methods=['GET', 'POST'])
@key_created
@key_not_activated
def registration():
    ad_query = Admin.query.filter_by().first()
    if ad_query is not None:
        return redirect(url_for('admin.login'))
    else:
        if current_user.is_authenticated:
            flash('You are aleady logged in.', 'info')
            return redirect(url_for('.dashboard'))
        else:
            password = 'password'
            org = Admin()
            org.name = 'admin'
            org.username = 'admin'
            org.employee_id = '123'
            org.email = 'admin@authelectric.io'
            org.phone_number = '1234567890'
            org.password = Admin.hash_password(password)
            db.session.add(org)
            db.session.commit()
            # flash('User signed up successfully', 'success')
            return redirect(url_for('admin.product_activate'))

#Admin Login
@admin.route('/login', methods=['GET', 'POST'])
@limiter.limit('30/hour')
@key_created
@no_admin
# create decorater to check if actually product is validated
def login():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        username = login_form.username.data.lower()
        password = login_form.password.data
        org = Admin.query.filter_by(username=username).first()
        if org is None or org.check_password(password) is False:
            flash('Incorrect Username or Password', 'danger')
        elif not org.email_verified:
            flash('Your email is not verified Please verify email first', 'danger')
        elif not org.is_active:
            flash('Your Account is disabled.')
        else:
            login_user(org)
            flash('You are logged in successfully', 'info')
            return redirect(url_for('.dashboard'))
    return render_template('admin/login.html', form=login_form)


@admin.route('/dashboard')
@login_required
@limiter.exempt
def dashboard():
    user_data = User.query.count()
    prop_data = Property.query.filter_by(is_active = True).count()
    bill_data = Metertransactionlog.query.count()
    server_data = Iotserver.query.filter_by(server_reg_confirm = True).count()
    admin_data = Admin.query.filter_by(is_active = True).count()
    device_data = Iotdevice.query.filter_by(device_reg_confirm = True).count()
    data = [user_data,prop_data,bill_data,server_data,admin_data,device_data]
    return render_template('admin/dashboard.html', data = data)



#Display users whose accounts are not yet activated
@admin.route('/approveuser')
@login_required
@limiter.exempt
@super_user
def approveuser():
    
    # property_data = Property.query.filter_by(is_active = False).all() 
    server_data = Iotserver.query.filter_by(server_reg_confirm = True).all()
    # org = User.query.filter_by(is_active=False).all()
    if server_data == [] or server_data is None:
        flash ('No Active Server Present. Please Activate a Server.', 'danger')
        return redirect(url_for('admin.iot_server_registration'))
    else:
        device_data = Iotdevice.query.filter_by(device_reg_confirm = True, property_assigned_status = False).all()
        if device_data == [] or device_data is None:
            flash ('No Active Device Present. Please Activate a Device.', 'danger')
            return redirect(url_for('admin.iot_device_registration'))
        else:
            property_owner_data = db.session.query(Property, User).outerjoin(User, User.id == Property.owner_id).filter(Property.is_active == False).all()
            if property_owner_data == [] or property_owner_data is None:
                return render_template('admin/approveuser.html', items=None)
            else:
                return render_template('admin/approveuser.html', items=property_owner_data)


@admin.route('/status/enable/accounts', methods=['GET', 'POST'])
@limiter.exempt
@login_required
@super_user
def enable_disabled_account():
    dev_id = []
    device_data = Iotdevice.query.filter(Iotdevice.device_reg_confirm == True, Iotdevice.property_assigned_status == True, Iotdevice.is_active == False).all()
    if device_data == [] or device_data == None:
        return  render_template('admin/enable_accounts.html', items=None)
    else:
        print("hey im here")
        for i in device_data:
            dev_id.append(i.id)
        items = []
        for i in dev_id:
            property_owner_data = db.session.query(Property, User).outerjoin(User, User.id == Property.owner_id).filter(Property.is_active == False, Property.device_id == i).all()
            # Join query .filter(hanfle is_active == false, device_id == i)
            print("Property data:", property_owner_data)
          
        return render_template('admin/enable_accounts.html', items = property_owner_data)


@admin.route('/logout')
@limiter.exempt
@login_required
def logout():
    logout_user()
    flash('You are logged out successfully.', 'info')
    return redirect(url_for('.login'))


#Check if admin email has been verified or not
@admin.route('/confirmation/<string:token>')
@limiter.exempt
@key_created
def email_confirmation(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = AdminToken.query.filter_by(
        token=token, token_type='email_confirmation').first()

    if not token_info:
        flash('Invalid email confirmation token', 'danger')
        return redirect(url_for('.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('.login')
    token_info.admin.email_verified = True
    token_info.admin.is_active = True
    db.session.commit()
    flash('Email has been verified', 'success')
    return redirect(url_for('admin.login'))


#Resend email to admin for verification in case of email token expiration
@admin.route('/resend-confirmation', methods=['GET', 'POST'])
@limiter.exempt
@key_created
def send_email_confirmation():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    form = ResendEmailConfirmationForm()
    if form.validate_on_submit():
        email = form.email.data
        org = Admin.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('admin.registration'))

        if org.email_verified:
            flash('Email address is already verified Please login', 'info')
            return redirect(url_for('admin.login'))

        email_conf_token = AdminToken.generate_token(
            'email_confirmation', org.id, 1800)
        send_confirmation_mail(org.email,
                               url_for('.email_confirmation',
                                       token=email_conf_token.token, _external=True))
        flash('The email confirmation link has been sent to your email. Please check your email', 'info')
        return redirect(url_for('.login'))
    return render_template('admin/resend_email_confirmation.html', form=form)



#Incase of password forgotten
@admin.route('/reset-password-request', methods=['GET', 'POST'])
@limiter.exempt
@key_created
@no_admin
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        org = Admin.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('admin.registration'))
        if not org.email_verified:
            flash('Email is not verified. Please verify email first', 'danger')
            return redirect(url_for('admin.login'))
        if not org.is_active:
            flash('Your account has been deactivated Please contact admin', 'info')
            return redirect(url_for('admin.login'))
        reset_password_token = AdminToken.generate_token(
            'reset_password', org.id, 1800)
        send_reset_password_mail(org.email,
                                 url_for('admin.reset_password',
                                         token=reset_password_token.token, _external=True))
        flash('Reset password link has been sent to your email address', 'info')
        return redirect(url_for('admin.login'))
    return render_template('admin/reset_password_request.html', form=form)

#Password reset
@admin.route('/reset-password/<string:token>', methods=['GET', 'POST'])
@limiter.exempt
@key_created
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))

    token_info = AdminToken.query.filter_by(
        token=token, token_type='reset_password').first()

    if not token_info:
        flash('Invalid Reset password token', 'danger')
        return redirect(url_for('admin.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('admin.login')
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        token_info.user.password = Admin.hash_password(password)
        db.session.commit()
        flash('Your password has been updated. Please login with new password', 'success')
        return redirect(url_for('admin.login'))
    return render_template('admin/reset_password.html', form=form)


#Approve the user and assign server and device
@admin.route('/user_profile/<string:token>/approve', methods=['GET', 'POST'])
@limiter.exempt
@login_required
@super_user
def user_profile_approve(token):
    
    form = AssignDeviceServerForm()
    print (form.server_id.data)
    print (form.device_id.data)
    if form.validate_on_submit():
        server = Iotserver.query.filter_by(id=form.server_id.data).first()
        if server is None or server == []:
            flash('Server Does Not Exist','danger')
            return redirect(url_for('admin.dashboard'))
        else:
            device = Iotdevice.query.filter_by(id=form.device_id.data ,property_assigned_status = False).first()
            if device is None or device == []:
                flash('Device Does Not Exist Or Device Already assigned','danger')
                return redirect(url_for('admin.dashboard'))
            else:
                prop_data = Property.query.filter_by(id=token).first()
                org = User.query.filter_by(id=prop_data.owner_id).first()
                if prop_data is None or prop_data == []:
                    flash('Property Does Not Exist','danger')
                    return redirect(url_for('admin.dashboard'))
                else:
                    if prop_data.device_id == 'NULL':
                        flash('Device ID already assigned','danger')
                        return redirect(url_for('admin.dashboard'))
                    else:
                        # -- Assigning Server Id & Device Id to the Property Table
                        prop_data.server_id = server.id
                        prop_data.is_active = True
                        prop_data.device_id = device.id
                        
                        # -- Assigning all necessary credentials to the device table
                        device.property_assigned_status = True
                        device.is_active = True
                        device.current_meter_readings = 0
                        device.previous_meter_readings = 0
                        
                        # -- Incrementing Property Data in the user table
                        prop_count = int(org.property_count)
                        prop_count += 1
                        org.property_count = prop_count
                        db.session.commit()

                        # -- Send the Owner the property approval
                        send_userapproval_mail(org.email)
                        flash('User Successfully Registered', 'info')
                        return redirect(url_for('admin.dashboard'))        
    return render_template('admin/assign_device_server.html', form=form)


#Incase of rejecting user remove record from database
@admin.route('/user_profile/<string:token>/reject' ,methods=['GET', 'POST'])
@limiter.exempt
@login_required
@super_user
def user_profile_reject(token):
    print(token)
    prop_data = Property.query.filter_by(id=token).first()
    org = User.query.filter_by(id=prop_data.owner_id).first()
    send_userreject_mail(org.email)
    UserToken.query.filter_by(user_id = org.id).delete()
    Property.query.filter_by(id=token).delete()   
    db.session.commit()
    
    return redirect(url_for('admin.approveuser'))


#Display all user details before approving or rejecting
@admin.route('/user_profile/<string:token>/<string:property_token>', methods=['GET', 'POST'])
@limiter.exempt
@login_required
@super_user
def user_profile(token, property_token):
    prop_data = Property.query.filter_by(id=property_token).all()
    org = User.query.filter_by(id=token).all()
    return render_template('admin/user_profile_approval.html', items=org, prop_data=prop_data)


#Login into account using email
@admin.route('/login/email', methods=['GET', 'POST'])
@limiter.exempt
@key_created
@no_admin
def login_email_request():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))
    form = LoginWithEmailForm()
    if form.validate_on_submit():
        email = form.email.data
        org = Admin.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('.registration'))
        if not org.email_verified:
            flash('Email is not verified. Please verify email first', 'danger')
            return redirect(url_for('admin.login'))
        if not org.is_active:
            flash('Your account has not been activated. Please wait.', 'info')
            return redirect(url_for('admin.login'))
        login_email_token = AdminToken.generate_token(
            'email_login', org.id, 1200)
        send_login_email_mail(org.email,
                                 url_for('.login_email',
                                         token=login_email_token.token, _external=True))
        flash('Login link has been sent to your email address', 'info')
        return redirect(url_for('admin.login'))
    return render_template('admin/login_with_email.html', form=form)



#Send email login link
@admin.route('/login/email/<string:token>', methods=['GET', 'POST'])
@limiter.exempt
@key_created
def login_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = AdminToken.query.filter_by(
        token=token, token_type='email_login').first()

    if not token_info:
        flash('Invalid Login token', 'danger')
        return redirect(url_for('.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email login link', 'danger')
        return redirect('.login')
    else:
        adminid = token_info.admin_id
        org = Admin.query.filter_by(id=adminid).first()
        login_user(org)
        return redirect(url_for('.dashboard'))


#Register IoT Server
@admin.route('/registration/iot_server', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def iot_server_registration():
    city_data = City.query.all()
    if city_data is None or city_data == []:
        flash ('Please Add a City-State from the Add City-State button on the left navigation.', 'danger')
        return redirect(url_for('admin.dashboard'))
    server_form = ServerRegistrationForm()
    if server_form.validate_on_submit():
        area = request.form.get('area_name').lower()
        city_enter_data = City.query.filter_by(city = area).all()
        if city_enter_data is None or city_enter_data == []:
            flash('Area Not Present.', 'danger')
            return redirect(url_for('admin.iot_server_registration'))
        else:
            server_name = server_form.server_reg_name.data.lower()
            pincode = server_form.pincode.data
            server_data = Iotserver.query.filter_by(server_reg_name = server_name).all()
            if server_data is None or server_data == []:
                org = Iotserver()
                org.server_reg_name = server_name
                org.area = area
                org.pincode = pincode
                org.api_key = Iotserver.generate_api_key()
                org.device_count = 0
                db.session.add(org)
                db.session.commit()
                flash('IoT Server Successfully Registered', 'info')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Data Already Present.', 'danger')
                return redirect(url_for('admin.iot_server_registration'))
            
    return render_template('admin/iotserver_registration.html', form=server_form, items = city_data)


#Register IoT device
@admin.route('/registration/iot_device', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def iot_device_registration():
    server_data = Iotserver.query.filter_by(server_reg_confirm = True , is_active = True).all()
    
    form = DeviceRegistrationForm()
    if form.validate_on_submit():
        print ('\n\nheyy')
        server_name = request.form.get('server_name').lower()
        server = Iotserver.query.filter_by(server_reg_name = server_name, server_reg_confirm = True, is_active = True).first()
        if  server == [] or server == None:
            flash('Server does not exist', 'danger')
            return redirect(url_for('admin.iot_device_registration'))
        else:
            device_data = Iotdevice.query.filter_by(device_reg_name=form.device_reg_name.data.lower()).first()
            if device_data is None or device_data == []:
                count = server.device_count
                print (type(count), count)
                count = int(count)
                count += 1
                print (type(count), count)
                server.device_count = count
                db.session.commit()
                org = Iotdevice()
                org.device_reg_name = form.device_reg_name.data.lower()
                org.address = form.address.data.lower()
                org.server_id = server.id
                org.housing_property = form.prop_type.data
                db.session.add(org)
                db.session.commit()
                flash('IoT Device Successfully Registered', 'info')
                return redirect(url_for('admin.dashboard'))
            else:
                flash('Data already present.', 'danger')
                return redirect(url_for('admin.iot_device_registration'))
    
    if server_data is None or server_data == []:
        flash ('Please add an IoT_Server First or Complete the registration of your IoT-Server.', 'danger')
        return redirect(url_for('admin.iot_server_registration'))
    else:
        return render_template('admin/iotdevice_registration.html', form=form, items = server_data)



#Display all active users
@admin.route('/status/user_status',methods=['GET','POST'])
@limiter.exempt
@login_required
def user_status():
    org = User.query.filter_by(is_active='true').all()
    if org == [] or org is None:
        return render_template('admin/user_status.html', items=None)
    else:
        return render_template('admin/user_status.html', items = org)


#Display all device status
@admin.route('/status/device_status',methods=['GET','POST'])
@limiter.exempt
@login_required
def device_status():
    active = []
    inactive = []
    device = Iotdevice.query.filter_by().all() 
    if device == [] or device is None:
        return render_template('admin/device_status.html', items = None)
    else:
        for data in device:
            if data.is_active == True and data.device_reg_confirm == True:
                active.append(data)
            else:
                inactive.append(data)
        print(active)
        print(inactive)
        return render_template('admin/device_status.html', active=active, inactive = inactive)

    
#Display all active servers
@admin.route('/status/server_status',methods=['GET','POST'])
@limiter.exempt
@login_required
def server_status():
    active = []
    inactive = []
    server = Iotserver.query.filter_by().all() 
    if server == [] or server is None:
        return render_template('admin/server_status.html', items = None)
    else:
        for data in server:
            if data.is_active == True and data.server_reg_confirm == True:
                active.append(data)
            else:
                inactive.append(data)
        print(active)
        print(inactive)
        return render_template('admin/server_status.html', active=active, inactive = inactive)


#Display admins profile
@admin.route('/profile')
@limiter.exempt
@login_required
def profile():
    return render_template('admin/profile.html', org=current_user)



#Update admin username
@admin.route('/update_username' , methods=['GET','POST'])
@limiter.exempt
@login_required
def update_username():
    form = UpdateUsernameForm()
    if form.validate_on_submit():
        old_username = form.old_username.data
        username = form.username.data
        org = Admin.query.filter_by(username=old_username).first()
        org.username = username
        db.session.add(org)
        db.session.commit()
        flash('Admin username changed', 'info')
        return redirect(url_for('.dashboard'))
    return render_template('admin/update_username.html', form=form)



#Update admin password
@admin.route('/update_password' , methods=['GET','POST'])
@limiter.exempt
@login_required
def update_password():
    form = UpdatePasswordForm()
    if form.validate_on_submit():
        name = current_user.name
        org = Admin.query.filter_by(name=name).first()
        if org is None or org.check_password(form.old_password.data) is False:
            flash('Incorrect Password', 'danger')
        else:
            org.password = Admin.hash_password(form.password.data)
            db.session.add(org)
            db.session.commit()
            flash('Admin Password Changed', 'info')
            return redirect(url_for('.dashboard'))
    return render_template('admin/update_password.html', form=form)


#Update admin email
@admin.route('/update_email' , methods=['GET','POST'])
@limiter.exempt
@login_required
def update_email():
    form = UpdateEmailForm()
    if form.validate_on_submit():
        org = Admin.query.filter_by(email=form.old_email.data).first()
        if org is None or org == []:
            flash('Incorrect Email Address', 'danger')
        else:
            org.email = form.email.data
            org.email_verified = False
            db.session.add(org)
            db.session.commit()
            email_conf_token = AdminToken.generate_token(
                'email_confirmation', org.id, 1800)
            send_confirmation_mail(org.email,
                                   url_for('.email_confirmation',
                                           token=email_conf_token.token, _external=True))
            flash('Admin email changed', 'info')
            return redirect(url_for('.logout'))
    return render_template('admin/update_email.html', form=form)


#Display IoT servers that are activated and completed registration process
@admin.route('/iot_server_login' , methods=['GET','POST'])
@limiter.exempt
@login_required
def iot_server_login():
    org = Iotserver.query.filter_by(is_active='true', server_reg_confirm='true').all()
    if org == [] or org is None:
        return render_template('admin/iot_server_login.html', items=None)
    else:
        return render_template('admin/iot_server_login.html', items = org)
    

#Validate IoT Server
@admin.route('/iot_server_login/<string:token>' , methods=['GET','POST'])
@limiter.exempt
@login_required
def iot_server_validate(token):
    email = current_user.email
    print('email:',email)
    data = {
        'email' : email
    }
    org = Iotserver.query.filter_by(id=token).first()
    encrypted_key = org.key
    decrypted_key = decrypt_key(encrypted_key)
    data = json.dumps(data)
    ct = encrypt_msg(data,decrypted_key)
    ciphertext = ct[0]
    iv = ct[1]
    data = {
            "ciphertext" : ciphertext,
            "iv" : iv 
        }
    print("data:",data)
    base_url = "http://{}:5001/api/v1/iot_server/login_request".format(org.remote_ip) 
    print (base_url)
    req_url = requests.post(url = base_url , json = data)
    if req_url.status_code == 200:
        content = req_url.json()
        ciphertext = content.get('ciphertext')
        iv = content.get('iv')
        ciphertext = ciphertext.encode()
        iv = iv.encode()
        iv = base64.b64decode(iv)
        ciphertext = base64.b64decode(ciphertext)
        pt = decrypt_msg(decrypted_key,iv,ciphertext)
        print('Plain Text :', pt)
        if pt == 'Suucessfully logged in':
            flash('Login Mail Sent For IoT Server Login.', 'info')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Error in logging into IoT Server', 'info')
            return redirect(url_for('admin.dashboard'))
        
    elif req_url.status_code == 404:
        flash('Error in logging into IoT Server', 'info')
        return redirect(url_for('admin.dashboard'))
    else :
        flash('Error in logging into IoT Server', 'info')
        return redirect(url_for('admin.dashboard'))
    

@admin.route('/product_activate' , methods=['GET','POST'])
@limiter.exempt
@key_not_activated
@no_admin
def product_activate():
    form = ActivateProduct()
    if form.validate_on_submit():
        activate_key = form.activation_key.data
        org = Productactivation.query.filter_by(product_key = activate_key)
        if org is None or org  == []:
            flash('Incorrect product activation key', 'danger')
            return redirect(url_for('admin.activate'))
        else:
            admin = Admin.query.filter_by(username = 'admin').first()
            admin_id = admin.id
            product_conf_token = AdminToken.generate_token('product_activation',admin_id,1800)
            token_info = AdminToken.query.filter_by(token_type='product_activation').first()
            token = token_info.token
            print('token: ',token)
            url = url_for('admin.register',token=token, _external=True)
            print('URL :', url)
            return redirect(url_for('admin.register',token=token, _external=True))
    return render_template('admin/product_activate.html', form = form)


@admin.route('/registration/admin/<string:token>' , methods=['GET','POST'])
@limiter.exempt
@key_created
@no_admin
def register(token):
    token_info = AdminToken.query.filter_by(token=token).first()
    if token_info is None:
        flash('Invalid URL Token', 'danger')
        return redirect(url_for('admin.activate'))
    else:
        if not token_info.is_valid():
            flash('Token is expired.', 'danger')
            return redirect(url_for('admin.activate'))
        # Enter only if the token is valid.
        activation_status = Productactivation.query.filter_by().first()
        if activation_status.activated == False:
            first_user = True
            if token_info.token_type == 'product_activation':
                form = SuperUserRegister()
                if form.validate_on_submit():
                    org = Admin.query.filter_by(username='admin').first()
                    org.name = form.name.data
                    org.username = form.username.data.lower()
                    org.employee_id = form.employee_id.data
                    org.email = form.email.data.lower()
                    org.phone_number = form.phone_number.data
                    org.password = Admin.hash_password(form.password.data)
                    org.role = 'super_user'
                    db.session.commit()
                    email_conf_token = AdminToken.generate_token('email_confirmation', org.id, 1800)
                    print('email conf token : ',email_conf_token)
                    send_confirmation_mail(org.email,url_for('.email_confirmation',
                                                token=email_conf_token.token, _external=True))
                    # Activation of product
                    org1 = Productactivation.query.filter_by(activated='False').first()
                    org1.activated = True
                    org1.product_conf_token = True
                    db.session.commit()
                    flash('User signed up successfully', 'success')
                    return redirect(url_for('admin.login'))
                return render_template('admin/register.html', form = form, item = first_user)
            else:
                flash ('Invalid Token Type', 'danger')
                return redirect(url_for('admin.activate'))
        else:
            first_user = False
            if token_info.token_type == 'admin_token':
                form = NewAdminRegistrationForm()
                if form.validate_on_submit():
                    admin_id = token_info.admin_id
                    org = Admin.query.filter_by(id = admin_id).first()
                    if org is None or org == []:
                        flash('You need to log in to add admins','danger')
                        return redirect(url_for('admin.login'))
                    else:
                        org.name = form.name.data
                        org.username = form.username.data.lower()
                        org.phone_number = form.phone_number.data
                        org.password = Admin.hash_password(form.password.data)
                        db.session.commit()
                        flash('User signed up successfully', 'success')
                        return redirect(url_for('admin.login'))
                return render_template('admin/register.html', form = form, item = first_user)
            else:
                flash ('Invalid Token Type', 'danger')
                return redirect(url_for('admin.activate'))



@admin.route('/add/admins' , methods=['GET','POST'])
@limiter.exempt
@login_required
@super_user
def add_admins():
    form = AddAdminsForm()
    if form.validate_on_submit():
        org = Admin()
        org.employee_id = form.employee_id.data
        org.email = form.email.data
        org.role = form.role.data
        db.session.add(org)
        db.session.commit()
        if org.role == 'super_user':
            super_user_conf_token = AdminToken.generate_token('admin_token', org.id, 1800)
            send_registration_mail(org.email, url_for('.registration_confirmation',token=super_user_conf_token.token, _external=True))
            flash('Super User is successfully created', 'info')
        elif org.role == 'admin':
            admin_token = AdminToken.generate_token('admin_token', org.id, 1800)
            send_registration_mail(org.email,url_for('.registration_confirmation',token=admin_token.token, _external=True))
            flash('Admin is successfully created', 'info')
        else:
            flash('error detected' , 'danger')
            return redirect(url_for('admin.dashboard'))
    return render_template('admin/add_admins.html', form=form)


@admin.route('/registration/confirmation/<string:token>')
@limiter.exempt
@key_created
def registration_confirmation(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))
    token_info = AdminToken.query.filter_by(token=token).first()

    if not token_info:
        flash('Invalid registration confirmation token', 'danger')
        return redirect(url_for('.login'))
    
    if not token_info.is_valid():
        flash('Token is expired. Please get new registration confirmation link', 'danger')
        return redirect('.login')
    token_info.admin.email_verified = True
    token_info.admin.is_active = True
    db.session.commit()
    flash('Email has been verified', 'success')
    return redirect(url_for('admin.register',token=token, _external=True))



@admin.route('/bill/paid/<string:token>')
@limiter.exempt
@login_required
def bill_paid(token):
    bill_id = token
    mtl_data = Metertransactionlog.query.filter_by(id = bill_id).first()
    if mtl_data is None:
        flash ('Data not found.' , 'danger')
        return(redirect(url_for('user.dashboard')))
    else:
        mtl_data.bill_paid = True
        db.session.commit()
        flash ('Successfully paid bill.' , 'info')
        return(redirect(url_for('user.dashboard')))


@admin.route('/bill/setslab', methods=['GET','POST'])
@limiter.exempt
@login_required
@super_user
def bill_setcost():
    
    form = SetBillSlabCostForm()
    if form.validate():
        
        if request.form['submit'] == 'delete':
            # -- accepting form data
            low_slab = form.low_slab.data
            high_slab = str(form.high_slab.data)
            housing_cost = str(form.housing_cost.data)
            commercial_cost = str(form.commercial_cost.data)
            penalty = form.penalty.data
            
            try:
                req = Slablog.query.filter_by(lower_slab = low_slab , upper_slab = high_slab , housing = housing_cost , commercial = commercial_cost , penalty = penalty).delete()
                
            except Exception as err:
                flash ('Data Incorrect. Please Try Again ', 'danger')
                return redirect(url_for('admin.bill_setcost'))
            else:
                db.session.commit()
                flash ('Data deleted Successfully.', 'info')
                return redirect(url_for('admin.bill_setcost'))
        elif request.form['submit'] == 'submit':
            # -- accepting form data
            low_slab = form.low_slab.data
            high_slab = str(form.high_slab.data)
            housing_cost = str(form.housing_cost.data)
            commercial_cost = str(form.commercial_cost.data)
            penalty = form.penalty.data
            
            slab_check = Slablog.query.filter_by(lower_slab = low_slab , upper_slab = high_slab , housing = housing_cost , commercial = commercial_cost , penalty = penalty).first()
            
            if slab_check == None or slab_check == []:
                slab_in_range = Slablog.query.all()
                print(len(high_slab))
                if high_slab  != 'MAX':
                    if int(low_slab) == int(high_slab) :
                        flash('lower limit and upper limit cannot be the same.', 'danger')
                        return redirect(url_for('admin.bill_setcost'))
                    if slab_in_range != []:
                        for i in slab_in_range:

                            # -- Check if lower slab is higher than upper slab
                            if int(low_slab) >= int(high_slab):
                                flash('Cannot Add Slab. As Lower is Higher than the upper slab.','danger')
                                return redirect(url_for('admin.bill_setcost'))                            

                            # -- Check if lower slab or high slab is in a pre defined range
                            lower_limit = int(i.lower_slab)
                            if i.upper_slab != 'MAX':

                                upper_limit = int(i.upper_slab)
                                if int(low_slab) in range(lower_limit,upper_limit+1) or int(high_slab) in range(lower_limit,upper_limit+1):
                                    flash('Please Set the slab right.','danger')
                                    return redirect(url_for('admin.bill_setcost'))    
                            else:
                                continue
                # If the upper Limit is Max then just check the lower limit
                for i in slab_in_range:
                    lower_limit = int(i.lower_slab)
                    if i.upper_slab != 'MAX':
                        upper_limit = int(i.upper_slab)
                        if int(low_slab) in range(lower_limit,upper_limit+1):
                            upper_limit = int(i.upper_slab)
                            flash('Please Set the slab right.','danger')
                            return redirect(url_for('admin.bill_setcost'))
                    else:
                        continue
                org = Slablog()
                org.lower_slab = low_slab
                org.upper_slab = high_slab
                org.housing = housing_cost
                org.commercial = commercial_cost
                org.penalty = penalty
                db.session.add(org)
                db.session.commit()
                flash('Added the slab successfully','info')
                return redirect(url_for('admin.bill_setcost'))
            else:
                flash("Slab already exists","danger")
                return redirect(url_for('admin.bill_setcost'))
    slab_data = Slablog.query.all()
    if slab_data == []:
        return render_template('admin/bill_setcost.html',form = form, items = None)
    else:
        return render_template('admin/bill_setcost.html',form = form, items = slab_data)





@admin.route('/bill/set/tax', methods=['GET','POST'])
@limiter.exempt
@login_required
@super_user
def bill_settax():
    form = SetBillTaxForm()
    if form.validate():
        tax_name = form.tax_name.data.upper()
        tax_rate = str(form.tax_rate.data)
        if request.form['submit'] == 'delete':
            
            try:
                req = Tax.query.filter_by(tax_name = tax_name, tax_rate = tax_rate).delete()

            except Exception as err:
                flash ('Data Incorrect. Please Try Again', 'danger')
                return redirect(url_for('admin.bill_settax'))
            else:
                db.session.commit()
                flash ('Data deleted Successfully.', 'info')
                return redirect(url_for('admin.bill_settax'))
        
        elif request.form['submit'] == 'submit':
            tax_details = Tax.query.filter_by(tax_name = tax_name).first()
            
            if tax_details == None or tax_details == []:
                org = Tax()
                org.tax_name = tax_name
                org.tax_rate = tax_rate
                db.session.add(org)
                db.session.commit()
                flash('Entry Added Successfully.','info')
                return redirect(url_for('admin.bill_settax'))

            else:
                flash("Tax Data already exists. Please check your data.","danger")
                return redirect(url_for('admin.bill_settax'))
    tax_data = Tax.query.all()
    if tax_data == []:
        return render_template('admin/bill_settax.html',form = form, items = None)
    
    return render_template('admin/bill_settax.html',form = form, items = tax_data)


@admin.route('/bill/miscellaneous/set/tax', methods=['GET','POST'])
@limiter.exempt
@login_required
@super_user
def miscellaneous_settax():
    form = SetMiscellaneousTaxForm()
    if form.validate():
        tax_name = form.tax_name.data.upper()
        tax_amount = str(form.tax_amount.data)
        if request.form['submit'] == 'delete':
            
            try:
                req = Miscellaneous.query.filter_by(name = tax_name, amount = tax_amount).delete()

            except Exception as err:
                flash ('Data Incorrect. Please Try Again', 'danger')
                return redirect(url_for('admin.miscellaneous_settax'))
            else:
                db.session.commit()
                flash ('Data deleted Successfully.', 'info')
                return redirect(url_for('admin.miscellaneous_settax'))
        
        elif request.form['submit'] == 'submit':
            tax_details = Miscellaneous.query.filter_by(name = tax_name).first()
            
            if tax_details == None or tax_details == []:
                org = Miscellaneous()
                org.name = tax_name
                org.amount = tax_amount
                db.session.add(org)
                db.session.commit()
                flash('Entry Added Successfully.','info')
                return redirect(url_for('admin.miscellaneous_settax'))

            else:
                flash("Tax Data already exists. Please check your data.","danger")
                return redirect(url_for('admin.miscellaneous_settax'))
    tax_data = Miscellaneous.query.all()
    if tax_data == []:
        return render_template('admin/bill_setmisctax.html',form = form, items = None)
    
    return render_template('admin/bill_setmisctax.html',form = form, items = tax_data)


@admin.route('/bill/pending', methods=['GET','POST'])
@limiter.exempt
@login_required
@super_user
def bill_pending():
    org = Metertransactionlog()
    pend = Metertransactionlog.query.filter_by(bill_paid = False).all()
    if pend == [] or pend is None:
        return render_template('admin/bill_pending.html', items = None)
    else:
        return render_template('admin/bill_pending.html', items=pend)


@admin.route('/bill/generate_bill', methods=['GET','POST'])
@limiter.exempt
@login_required
@super_user
def generate_bill():
    slab_data = Slablog.query.all()
    if slab_data is None or slab_data == []:
        flash ('Please Set the Slab in the billsection First.', 'danger')
        return redirect(url_for('admin.bill_setcost'))
    else:
        for i in slab_data:
            if i.upper_slab == 'MAX':
                iot_server_data = Iotserver.query.filter_by(server_reg_confirm = True).all()
                if iot_server_data is None or iot_server_data == []:
                    flash ('You do not have any active IoT Servers.', 'danger')
                    return redirect(url_for('admin.dashboard'))
                else:
                    iot_device_data = Iotdevice.query.filter_by(device_reg_confirm = True, is_active = True).all()
                    if iot_device_data is None or iot_device_data == []:
                        flash ('You do not have any active IoT Devices.', 'danger')
                        return redirect(url_for('admin.dashboard'))

                    prop_data = Property.query.filter_by(is_active = True).all()
                    if prop_data is None or prop_data == []:
                        flash ('You do not have any active Consumers.', 'danger')
                        return redirect(url_for('admin.dashboard'))

                    for i in prop_data:
                        i.bill_gen_status = False
                        db.session.commit()

                    for i in iot_server_data:

                        if i.remote_ip is None:
                            continue
                        else:
                            base_url = 'http://{}:5001/api/v1/iot_server/generate_bill'.format(i.remote_ip)
                            print(base_url)
                            try:
                                req_url = requests.post(url = base_url)
                                req_url.raise_for_status()
                                message = content.get('message')
                                if message == 'ALL_OK':
                                    continue
                            except HTTPError as http_err:
                                continue
                            except Exception as err:
                                continue
                            
                    flash('Billing Request Sent', 'info')
                    return redirect(url_for('admin.dashboard'))
            else:
                continue
        flash ('Please set the MAX slab to prevent errors.', 'danger')
        return redirect(url_for('admin.bill_setcost'))


# @admin.route('/bill/generate_bill/late', methods=['GET','POST'])
# @limiter.exempt
# @login_required
# def generate_bill_late():
#     prop_data = Property.query.filter_by(is_active = True, bill_gen_status = False).all()
#     if prop_data is None or prop_data == []:
#         flash ('You do not have any Late Requests.', 'danger')
#         return redirect(url_for('admin.bill'))
    
#     # bill_req_def_data = Billrequestdefaulters.query.filter_by(property_id = prop_data.id).all()
#     # if bill_req_def_data is None or bill_req_def_data == []:
#     #     flash ('You do not have any Late Requests.', 'danger')
#     #     return redirect(url_for('admin.bill'))

#     is_data = []
#     for i in prop_data:
#         is_data.append(i.server_id)

#     is_data = remove_duplicate_iot_server(is_data)
#     print('server_id L', is_data)
#     for i in is_data:
#         iot_server_data = Iotserver.query.filter_by(server_reg_confirm = True, id = i).all()
#         if iot_server_data is None or iot_server_data == []:
#             flash ('IoT Server Not Present.', 'danger')
#             return redirect(url_for('admin.bill'))
#         else:
#             iot_device_data = Iotdevice.query.filter_by(device_reg_confirm = True, is_active = True , server_id = i).all()
#             if iot_device_data is None or iot_device_data == []:
#                 flash ('IoT Device Not Present.', 'danger')
#                 return redirect(url_for('admin.bill'))



#             for i in iot_server_data:

#                 if i.remote_ip is None:
#                     continue
#                 else:
#                     base_url = 'http://{}:5001/api/v1/iot_server/generate_bill/late'.format(i.remote_ip)
#                     print(base_url)
#                     try:
#                         req_url = requests.post(url = base_url)
#                         req_url.raise_for_status()
#                         message = content.get('message')
#                         if message == 'ALL_OK':
#                             continue
#                     except HTTPError as http_err:
#                         continue
#                     except Exception as err:
#                         continue
    
#     flash('Late Billing Request Sent', 'info')
#     return redirect(url_for('admin.bill'))


@admin.route('/bill/sample', methods=['GET','POST'])
@limiter.exempt
@login_required
def bill_sample():
    salblog_data = Slablog.query.all()
    # pend = Metertransactionlog.query.filter_by(bill_paid = False).all()
    if salblog_data == [] or salblog_data is None:
        flash ('Please Set the Slab in the billsection First.', 'danger')
        return redirect(url_for('admin.bill_setcost'))
    else:
        for i in salblog_data:
            if i.upper_slab == 'MAX':
                bill = main_billing(500, True)
                print (type(bill))
                bill = [bill]
                print_bill_data = [{
                    'bill_no' : 123,
                    'date' : '20/03/2020',
                    'owner_details' : [{'owner_name' : 'ABC DEF', 'property_name' : 'Building Name', 'pincode' : '1111'}],
                    'tenant_details' : [{'tenant_name' : 'TEN DEF'}],
                    'bill_details' : bill
                }]
                print ('\n\n\n')
                print (print_bill_data)
                return render_template('admin/bill_sample.html', bill_dict = print_bill_data)
            else:
                continue
        flash ('Please set the MAX slab to prevent errors.', 'danger')
        return redirect(url_for('admin.bill_setcost'))



@admin.route('/add/city-state', methods=['GET','POST'])
@limiter.exempt
@login_required
def add_citystate():

    city_data = City.query.all()
    form = AddStateCityForm()
    if form.validate():
        if request.form['submit'] == 'delete':
            state = request.form.get('state_name').lower()
            city = form.city.data.lower()
            print (state)
            print (city)
            city_enter_data = City.query.filter_by(state = state, city = city).all()
            print (city_enter_data)
            if city_enter_data is None or city_enter_data == []:
                flash('Data Not Present.','danger')
                return redirect(url_for('admin.add_citystate'))
            else:
                City.query.filter_by(state = state, city = city).delete()
                db.session.commit()
                flash('Data Deleted.','info')
                return redirect(url_for('admin.add_citystate'))
        elif request.form['submit'] == 'submit':
            state = request.form.get('state_name').lower() # property = request.form.get('property')
            city = form.city.data.lower()
            print (state)
            print (city)
            city_enter_data = City.query.filter_by(state = state, city = city).first()
            print (city_enter_data)
            if city_enter_data is None or city_enter_data == []:
                new_state = City()
                new_state.state = state
                new_state.city = city
                db.session.add(new_state)
                db.session.commit()
                flash('Entry Added','info')
                return redirect(url_for('admin.add_citystate'))
            else:
                flash('Data Already Present','danger')
                return redirect(url_for('admin.add_citystate'))
    
    # if needed keep appending state names here. Also dont forget to append them iot_sec -> iot_security -> users -> forms -> add_property form
    state_info = ['goa','gujarat','kerala','madhya pradesh','maharashtra','tamil nadu','telangana','uttar pradesh','uttarakhand','west bengal']
    if city_data is None or city_data == []:
        
        return render_template('admin/add_citystate.html', items=None, form=form, state_info = state_info)
    else:
        
        return render_template('admin/add_citystate.html', items=city_data, form=form, state_info = state_info)


@admin.route('/support-query', methods=['GET','POST'])
@limiter.exempt
@login_required
def supportquery():
    support_data = Supportquery.query.filter_by(status = False).all()
    if support_data == [] or support_data is None:
        flash ('No Queries Present at the moment.', 'danger')
        return render_template ('admin/support_query.html', items = None)
    else:
        return render_template ('admin/support_query.html', items = support_data)


@admin.route('/support-query/<string:user_id>/<string:support_id>/completed', methods=['GET','POST'])
@limiter.exempt
@login_required
def supportquery_completed(user_id, support_id):
    user_id = int(user_id)
    support_id = int(support_id)
    user_data = User.query.filter_by(id = user_id).first()
    
    # -- Fetching User Data
    if user_data is None:
        flash ('Encountered an error in fetching data.', 'danger')
        return redirect(url_for('admin.supportquery'))
    
    # -- Fetching Query Data
    supp_data = Supportquery.query.filter_by(id = support_id).first()
    if supp_data is None:
        flash ('Encountered an error in fetching data.', 'danger')
        return redirect(url_for('admin.supportquery'))
    
    supp_data.status = True
    db.session.commit()

    send_support_query_completed_mail(user_data.email,support_id)
    flash ('Operation completed successfully.', 'info')
    return redirect(url_for('admin.supportquery'))



@admin.route('/support-query/<string:user_id>/<string:support_id>/pending', methods=['GET','POST'])
@limiter.exempt
@login_required
def supportquery_pending(user_id, support_id):
    user_id = int(user_id)
    support_id = int(support_id)
    user_data = User.query.filter_by(id = user_id).first()
    
    # -- Fetching User Data
    if user_data is None:
        flash ('Encountered an error in fetching data.', 'danger')
        return redirect(url_for('admin.supportquery'))
    
    # -- Fetching Query Data
    supp_data = Supportquery.query.filter_by(id = support_id).first()
    if supp_data is None:
        flash ('Encountered an error in fetching data.', 'danger')
        return redirect(url_for('admin.supportquery'))
    
    
    send_support_query_pending_mail(user_data.email,support_id)
    flash ('Operation completed successfully.', 'info')
    return redirect(url_for('admin.supportquery'))
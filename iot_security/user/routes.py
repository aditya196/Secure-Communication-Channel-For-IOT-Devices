from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from iot_security.user.forms import (SignupForm, LoginForm,
                                              ResendEmailConfirmationForm,
                                              ResetPasswordRequestForm,
                                              ResetPasswordForm,
                                              LoginWithEmailForm,
                                              ValidateotpForm,
                                              ResendValidateotpForm,
                                              AddPropertyForm,
                                              AddTenantCheck,
                                              SupportQueryForm)
from iot_security.models import User, UserToken, City, Property, Tenant, Supportquery, Metertransactionlog
from iot_security.models.utils import rand_pass
from iot_security import db
from iot_security import limiter
import json
from iot_security.user.utils import (send_confirmation_mail,
                                    send_reset_password_mail,
                                    send_login_email_mail,
                                    send_tenant_approval_check_mail,
                                    send_ownerapproval_mail,
                                    send_tenantapproval_mail,
                                    send_ownerreject_mail,
                                    send_tenantreject_mail,
                                    send_owner_remove_tenant_mail,
                                    send_tenant_remove_tenant_mail,
                                    send_owner_leave_tenant_mail,
                                    send_tenant_leave_tenant_mail,
                                    property_present_active,
                                    property_management_disable,
                                    send_support_query_mail)

user = Blueprint('user', __name__)



@user.route('/')
@limiter.exempt
def user_index():
    return render_template('user_interface/index.html')





# Signup form for user
@user.route('/signup', methods=['GET', 'POST'])
@limiter.limit("20/hour")
def signup():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    signup_form = SignupForm()
    if signup_form.validate_on_submit():
        org = User()
        org.name = signup_form.name.data
        org.username = signup_form.username.data.lower()
        org.email = signup_form.email.data.lower()
        org.phone_number = signup_form.phone_number.data
        org.password = User.hash_password(signup_form.password.data)
        org.terms_and_conditions_agreed = signup_form.terms_and_conditions.data
        org.aadhar_number = signup_form.aadhar_number.data
        org.property_count = 0
        try :
            db.session.add(org)
            db.session.commit()
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Login Failed', 'danger')
            return redirect(url_for('user.signup'))
        else:
            email_conf_token = UserToken.generate_token(
                'email_confirmation', org.id, 1800)
            User.generate_smcode(org.id, 180)
            try:
                send_confirmation_mail(org.email,
                                   url_for('user.email_confirmation',
                                           token=email_conf_token.token, _external=True))
            except Exception as err:
                print ('Error Logged : ', err)
                flash('Email sending failed', 'danger')
                return redirect(url_for('user.signup'))
            else:
                return redirect(url_for('user.validate_OTP'))

    return render_template('user_interface/signup.html', form=signup_form)


# Login page for user
@user.route('/login', methods=['GET', 'POST'])
@limiter.limit("15/hour")
def login():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    login_form = LoginForm()
    if login_form.validate_on_submit():
        username = login_form.username.data.lower()
        password = login_form.password.data
        org = User.query.filter_by(username=username).first()
        if org is None or org.check_password(password) is False:
            flash('Incorrect Username or Password', 'danger')
        elif not org.email_verified:
            flash('Your email is not verified Please verify email first', 'danger')
            return redirect(url_for('.send_email_confirmation'))
        elif not org.valid_sm_code:
            flash('Your OTP is not verified Please verify OTP first', 'danger')
            return redirect(url_for('.resend_validate_OTP'))
        elif not org.is_active:
            flash('Your Account is disabled. Please contact admin')
        else:
            login_user(org, remember=True)
            flash('You have logged in successfully', 'info')
            tenant_data = Tenant.query.filter_by(user_id = org.id).first()
            if tenant_data is None:
                owner_data = Property.query.filter((Property.owner_id == org.id) | (Property.tenant_id == org.id)).first()
                # tenant_data = Property.query.filter_by(tenant_id = org.id).first()
                print ('owner data :',owner_data)
                if owner_data is None or owner_data == []:
                    flash('Please add a property', 'info')
                    return redirect(url_for('user.propertymanagement'))
                else:
                    return redirect(url_for('user.dashboard'))
            else:
                owner_data = Property.query.filter((Property.owner_id == org.id) | (Property.tenant_id == tenant_data.id)).first()
                # tenant_data = Property.query.filter_by(tenant_id = org.id).first()
                print ('owner data :',owner_data)
                if owner_data is None or owner_data == []:
                    flash('Please add a property', 'info')
                    return redirect(url_for('user.propertymanagement'))
                else:
                    return redirect(url_for('user.dashboard'))
    return render_template('user_interface/login.html', form=login_form)


# Validate users OTP
@user.route('/validate_OTP', methods=['GET', 'POST'])
@limiter.limit("15/hour")
def validate_OTP():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    otp_form = ValidateotpForm()
    if otp_form.validate_on_submit():
        valid_sm = User.query.filter_by(sm_code=otp_form.otp.data).first()

        if valid_sm is None:
            flash('Invalid OTP', 'danger')
            return redirect(url_for('.login'))

        if not valid_sm.is_valid():
            flash('OTP is expired. Please get new OTP', 'danger')
            return redirect('.login')
        else:
            valid_sm.valid_sm_code = True
            db.session.commit()
            flash('OTP verified', 'success')
            flash('User signed up successfully', 'success')
            return redirect(url_for('.login'))
    return render_template('user_interface/validate_otp.html', form=otp_form)



# Resend OTP incase of expiry
@user.route('/resend_validate_OTP', methods=['GET', 'POST'])
@limiter.limit("20/hour")
def resend_validate_OTP():
    if current_user.is_authenticated:
        flash('You are aleady logged in.', 'info')
        return redirect(url_for('.dashboard'))
    otp_form = ResendValidateotpForm()
    if otp_form.validate_on_submit():
        valid_smcode = User.query.filter_by(phone_number=otp_form.phone.data).first()
    
        if valid_smcode is None:
            flash('Mobile Number Not Registered', 'danger')
            return redirect(url_for('.signup'))
        elif valid_smcode.valid_sm_code:
            flash('OTP Already Validated', 'danger')
            return redirect(url_for('.login'))
        else:
            User.generate_smcode(valid_smcode.id, 1800)
            flash('OTP Sent', 'success')
            return redirect(url_for('.validate_OTP'))
    return render_template('user_interface/resend_validate_otp.html', form=otp_form)
    

@user.route('/dashboard')
@limiter.limit("60/hour")
@login_required
@property_present_active
def dashboard():
    return render_template('user_interface/dashboard.html')


@user.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You are logged out successfully.', 'info')
    return redirect(url_for('.login'))

# Confirm whether users email is verified or not
@user.route('/confirmation/<string:token>')
def email_confirmation(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = UserToken.query.filter_by(
        token=token, token_type='email_confirmation').first()

    if not token_info:
        flash('Invalid email confirmation token', 'danger')
        return redirect(url_for('.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('.login')
    token_info.user.email_verified = True
    token_info.user.is_active = True
    
    db.session.commit()
    flash('Email has been verified', 'success')
    return redirect(url_for('.login'))


# Send email to user for verification
@user.route('/resend-confirmation', methods=['GET', 'POST'])
def send_email_confirmation():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    form = ResendEmailConfirmationForm()
    if form.validate_on_submit():
        email = form.email.data
        org = User.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('.signup'))

        if org.email_verified:
            flash('Email address is already verified Please login', 'info')
            return redirect(url_for('.login'))

        email_conf_token = UserToken.generate_token(
            'email_confirmation', org.id, 1800)
        send_confirmation_mail(org.email,
                               url_for('.email_confirmation',
                                       token=email_conf_token.token, _external=True))
        flash('The email confirmation link has been sent to your email. Please check your email', 'info')
        return redirect(url_for('.login'))
    return render_template('user_interface/resend_email_confirmation.html', form=form)


# Reset password incase forgotten
@user.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        email = form.email.data
        org = User.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('.signup'))
        if not org.email_verified:
            flash('Email is not verified. Please verify email first', 'danger')
            return redirect(url_for('.login'))
        if not org.is_active:
            flash('Your account has been deactivated Please contact admin', 'info')
            return redirect(url_for('.login'))
        reset_password_token = UserToken.generate_token(
            'reset_password', org.id, 1800)
        try:
            send_reset_password_mail(org.email,
                                 url_for('.reset_password',
                                         token=reset_password_token.token, _external=True))
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Email sending failed', 'danger')
            return redirect(url_for('user.login')) 
        else:
            flash('Reset password link has been sent to your email address', 'info')
            return redirect(url_for('.login'))
    return render_template('user_interface/reset_password_request.html', form=form)


# Reset password
@user.route('/reset-password/<string:token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = UserToken.query.filter_by(
        token=token, token_type='reset_password').first()

    if not token_info:
        flash('Invalid Reset password token', 'danger')
        return redirect(url_for('.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email confirmation link', 'danger')
        return redirect('.login')
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        token_info.user.password = User.hash_password(password)
        db.session.commit()
        flash('Your password has been updated. Please login with new password', 'success')
        return redirect(url_for('.login'))
    return render_template('user_interface/reset_password.html', form=form)



# Display users profile
@user.route('/profile')
@limiter.limit("20/hour")
@login_required
@property_present_active
def profile():
    return render_template('user_interface/profile.html', org=current_user)



# Login into account using email
@user.route('/login/email', methods=['GET', 'POST'])
@limiter.limit("10/hour")
def login_email_request():
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))
    form = LoginWithEmailForm()    
    if form.validate_on_submit():
        email = form.email.data
        org = User.query.filter_by(email=email).first()
        if not org:
            flash('Email address is not registered with us. Please signup', 'info')
            return redirect(url_for('user.signup'))
        if not org.email_verified:
            flash('Email is not verified. Please verify email first', 'danger')
            return redirect(url_for('user.login'))
        if not org.is_active:
            flash('Your account has not been verified. Please wait.', 'info')
            return redirect(url_for('user.login'))
        login_email_token = UserToken.generate_token(
            'email_login', org.id, 1200)
        try:
            send_login_email_mail(org.email,
                                 url_for('.login_email',
                                         token=login_email_token.token, _external=True))
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Email sending failed', 'danger')
            return redirect(url_for('user.login'))

        else:
            flash('Login link has been sent to your email address', 'info')
            return redirect(url_for('user.login'))
    return render_template('user_interface/login_with_email.html', form=form)



# Resend email login link
@user.route('/login/email/<string:token>', methods=['GET', 'POST'])
@limiter.exempt
def login_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('.dashboard'))

    token_info = UserToken.query.filter_by(
        token=token, token_type='email_login').first()

    if not token_info:
        flash('Invalid Login token', 'danger')
        return redirect(url_for('user.login'))
    if not token_info.is_valid():
        flash('Token is expired. Please get new email login link', 'danger')
        return redirect('user.login')
    else:
        userid = token_info.user_id
        org = User.query.filter_by(id=userid).first()
        login_user(org)
        return redirect(url_for('user.dashboard'))


@user.route('/property/management', methods=['GET', 'POST'])
@limiter.limit("40/hour")
@login_required
@property_management_disable
def propertymanagement():
    # Figure out why this is done
    if True:
        return render_template('user_interface/propertymanagement.html', data = 'true')
    else:
        return render_template('user_interface/propertymanagement.html', data = 'false')


@user.route('/add/property', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def addproperty():
    add_property_token = UserToken.generate_token(
            'property_registration', current_user.id, 1200)
    token_info = UserToken.query.filter_by(token_type='property_registration', user_id = current_user.id).first()
    token = token_info.token
    print('token: ',token)
    return redirect(url_for('user.addpropertycheck',token=token, _external=True))


@user.route('/add/property/<string:token>', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def addpropertycheck(token):
    token_info = UserToken.query.filter_by(token=token).first()
    if token_info is None:
        flash('Invalid URL Token', 'danger')
        return redirect(url_for('user.propertymanagement'))
    else:
        if not token_info.is_valid():
            flash('Expired Token', 'danger')
            return redirect(url_for('user.propertymanagement'))
    
        form = AddPropertyForm()
        form.city.choices = [(city.city, city.city) for city in City.query.filter_by(state=form.state.data).all()]
        
        if form.validate_on_submit():
            print(current_user.id)
            print(form.state.data)
            print(form.pincode.data)
            print(form.building_name.data)
            print(form.street_name.data)
            print(form.city.data)
            token_info.token = rand_pass(16)
            db.session.commit()

            # -- Work From Here!! First add them to db then send for approval to admin.
            org = Property()
            org.flat_no = form.house_number.data
            org.building_name = form.building_name.data.lower()
            org.state = form.state.data.lower()
            org.pincode = form.pincode.data
            org.city = form.city.data.lower()
            org.street = form.street_name.data
            org.owner_id = current_user.id
            db.session.add(org)
            db.session.commit()
            flash ('Your poperty information is being validated. You will be notified when the registration is completed.', 'info')
            return redirect(url_for('user.propertymanagement'))
    return render_template('user_interface/add_property.html', form = form)


@user.route('/add/property/tenant', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def addtenant():
    add_tenant_token = UserToken.generate_token(
            'tenant_registration', current_user.id, 1200)
    token_info = UserToken.query.filter_by(token_type='tenant_registration', user_id = current_user.id).first()
    token = token_info.token
    print('token: ',token)
    return redirect(url_for('user.addtenantcheck',token=token, _external=True))



@user.route('/add/property/tenant/<string:token>', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def addtenantcheck(token):
    property_data = Property.query.filter_by(owner_id=current_user.id, tenant_id = None, is_active = True).all()
    token_info = UserToken.query.filter_by(token=token).first()
    if token_info is None:
        flash('Invalid URL Token', 'danger')
        return redirect(url_for('user.dashboard'))
    else:
        if not token_info.is_valid():
            flash('Expired Token', 'danger')
            return redirect(url_for('user.dashboard'))
        form = AddTenantCheck()
        if form.validate_on_submit():
            username = form.username.data
            phone_number = form.phone_number.data
            property = request.form.get('property')
            user_tenant_data = User.query.filter_by(username = username, phone_number = phone_number).first()
            if user_tenant_data is None:
                flash ('Failed to fetch Tenant Data', 'danger')
                return redirect(url_for('user.dashboard'))
            else:
                tenant_property_data = Property.query.filter_by(building_name = property).first()
                if tenant_property_data is None:
                    flash ('failed to fetch property details. Please try again', 'danger')
                    return redirect(url_for('user.dashboard'))
                else:
                    # To - Do from here
                    tenant_data = Tenant.query.filter_by(user_id = user_tenant_data.id).first()
                    if tenant_data is None:
                        new_tenant_data = Tenant()
                        new_tenant_data.user_id = user_tenant_data.id
                        db.session.add(new_tenant_data)
                        db.session.commit()
                    tenant_data = Tenant.query.filter_by(user_id = user_tenant_data.id).first()
                    tenant_property_data.tenant_id = tenant_data.id
                    db.session.commit()

                    tenant_approval_token = UserToken.generate_token('tenant_approval', user_tenant_data.id, 1200)
                    try:
                        send_tenant_approval_check_mail(user_tenant_data.email,
                                 url_for('user.tenantpropertycheck',
                                         token=tenant_approval_token.token, property_id = str(tenant_property_data.id) , _external=True))
                    except Exception as err:
                        print ('Error Logged : ', err)
                        flash('Email sending failed', 'danger')
                        return redirect(url_for('user.dashboard'))
                    else:
                        flash('Approval link has been sent to your Tenant.', 'info')
                        return redirect(url_for('user.dashboard'))
            print (property)
    if property_data is None or property_data == []:
        return render_template('user_interface/add_tenant.html', form = form, property = None)
    else:
        return render_template('user_interface/add_tenant.html', form = form, property = property_data)



@user.route('/add/property/tenant_approval/<string:token>/<string:property_id>', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def tenantpropertycheck(token,property_id):
    print ('heyyyy')
    property_id = int(property_id)
    print ('Token :', token)
    print ('Property ID :', property_id)
    token_info = UserToken.query.filter_by(token=token, user_id = current_user.id).first()
    if token_info is None:
        flash('Invalid URL Token', 'danger')
        return redirect(url_for('user.dashboard'))
    else:
        if not token_info.is_valid():
            flash('Expired Token', 'danger')
            return redirect(url_for('user.dashboard'))
        else:
            tenant_data = Tenant.query.filter_by(user_id=token_info.user_id).first()
            if tenant_data is None:
                flash('Tenant does not exist.', 'danger')
                return redirect(url_for('user.dashboard'))
            # print (tenant_data.user_id,'\n',property_id)
            property_data = Property.query.filter_by(tenant_id=tenant_data.id, id = property_id, is_active = True).first()
            if property_data is None:
                flash('Sorry somewthing went wrong', 'danger')
                return redirect(url_for('user.dashboard'))
            else:
                owner_data = User.query.filter_by(id=property_data.owner_id).first()
                if owner_data is None:
                    flash('Sorry Could Not Fetch Owner Data.', 'danger')
                    return redirect(url_for('user.dashboard'))
                else:
                    return render_template ('user_interface/tenant_property_check.html', prop_data=property_data, owner_data=owner_data)


@user.route('/add/property/tenant/<string:token>/approve', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def tenant_property_approve(token):
    prop_data = Property.query.filter_by(id=token).first()
    if prop_data is None or prop_data == []:
        flash('Property Does Not Exist','danger')
        return redirect(url_for('user.dashboard'))
    else:
        tenant_data = Tenant.query.filter_by(id=prop_data.tenant_id).first()
        # print ('\n\n\n', tenant_data)
        owner_data = User.query.filter_by(id=prop_data.owner_id).first()
        # print ('\n\n\n', owner_data)
        tenant_mail_data = User.query.filter_by(id=tenant_data.user_id).first()
        prop_data.tenant_reg_confirm = True
        db.session.commit()
        
        prop_count = int(tenant_data.property_count)
        prop_count += 1
        tenant_data.property_count = prop_count
        db.session.commit()
        try:
            send_ownerapproval_mail(owner_data.email)
            send_tenantapproval_mail(tenant_mail_data.email)
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Email sending failed', 'danger')
            return redirect(url_for('user.dashboard'))

        else:
            UserToken.query.filter_by(user_id = tenant_data.user_id).delete()
            flash ('Property Successfully Added', 'info')
            return (redirect(url_for('user.dashboard')))



@user.route('/add/property/tenant/<string:token>/reject', methods=['GET', 'POST'])
@limiter.exempt
@login_required
def tenant_property_reject(token):
    print(token)
    prop_data = Property.query.filter_by(id=token).first()
    owner_data = User.query.filter_by(id=prop_data.owner_id).first()
    tenant_data = Tenant.query.filter_by(id=prop_data.tenant_id).first()
    tenant_mail_data = User.query.filter_by(id=tenant_data.user_id).first()
    if prop_data is None and owner_data is None and tenant_data is None and tenant_mail_data is None:
        flash ('Something Went Wrong', 'info')
        return redirect(url_for('user.dashboard'))
    else:
        print ('\n\n\n User Token : ', tenant_data.user_id)
        UserToken.query.filter_by(user_id = tenant_data.user_id).delete()
        
        prop_data.tenant_id = None
        prop_data.tenant_reg_confirm = False
        db.session.commit()
        try:
            send_ownerreject_mail(owner_data.email)
            send_tenantreject_mail(tenant_mail_data.email)
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Email sending failed', 'danger')
            return redirect(url_for('user.dashboard'))

        else:    
            prop_count = int(tenant_data.property_count)
            if prop_count > 0:
                flash ('Successfully Rejected the property.','info')
                return redirect(url_for('user.dashboard'))
            # if property count is 0 then delete the tenant entry
            val = Tenant.query.filter_by(user_id=tenant_data.user_id).delete()

            print ('\n\n\n\n Delete Operation : ', val, tenant_data.user_id)
            flash ('Successfully Rejected the property.','info')
            return redirect(url_for('user.dashboard'))



@user.route('/city/<state>')
@limiter.exempt
@login_required
def city(state):
    cities = City.query.filter_by(state = state).all()
    cityArray = []
    for city in cities:
        cityObj={}
        cityObj['id'] = city.id
        cityObj['name'] = city.city
        cityArray.append(cityObj)
    return jsonify({'cities':cityArray})    


@user.route('/property/owned' ,methods=['GET', 'POST'])
@login_required
@property_present_active
def displayownedproperty():
    user_id = current_user.id
    prop_data = Property.query.filter_by(owner_id = user_id, is_active = True).all()
    if prop_data is None or prop_data == []:
        return render_template('user_interface/display_owned_property.html', owner = None)
    else:
        
        return render_template('user_interface/display_owned_property.html', owner = prop_data, )

@user.route('/property/rented' ,methods=['GET', 'POST'])
@login_required
@property_present_active
def displayrentedproperty():
    user_id = current_user.id
    tenant_data = Tenant.query.filter_by(user_id = user_id).first()
    if tenant_data is None or tenant_data == []:
        return render_template('user_interface/display_rented_property.html', rented = None)
    
    prop_data = Property.query.filter_by(tenant_id = tenant_data.id, is_active = True).all()
    if prop_data is None or prop_data == []:
        return render_template('user_interface/display_rented_property.html', rented = None)
    else:
        return render_template('user_interface/display_rented_property.html', rented = prop_data)


@user.route('/property/display/view_more/<string:token>')
@login_required
@property_present_active
def viewmoreproperty(token):
    return render_template('user_interface/view_more_owned_property.html')


@user.route('/property/display/current_reading/<string:token>')
@login_required
@property_present_active
def current_meter_reading(token):
    user_id = current_user.id
    prop_id = token
    labels = []
    values = []
    tenant_data = Tenant.query.filter_by(user_id = user_id).first()
    if tenant_data is None:
        owner_data = Property.query.filter((Property.owner_id == user_id) | (Property.tenant_id == user_id)).first()
        
        if owner_data is None or owner_data == []:
            flash('Property data not found.', 'info')
            return redirect(url_for('user.dashboard'))
        else:
            mtl_data = Metertransactionlog.query.all()
            if mtl_data == []:
                flash('Bill not yet generated.', 'info')
                return redirect(url_for('user.dashboard'))
            for i in mtl_data:
                labels.append(i.month)
                values.append(i.meter_reading)
            return render_template('user_interface/view_current_reading.html', labels = labels, values = values, items = mtl_data)
    else:
        owner_data = Property.query.filter((Property.owner_id == user_id) | (Property.tenant_id == tenant_data.id)).first()
        # tenant_data = Property.query.filter_by(tenant_id = org.id).first()
        print ('owner data :',owner_data)
        if owner_data is None or owner_data == []:
            flash('Property data not found.', 'info')
            return redirect(url_for('user.dashboard'))
        else:
            mtl_data = Metertransactionlog.query.all()
            if mtl_data == []:
                flash('Bill not yet generated.', 'info')
                return redirect(url_for('user.dashboard'))
            for i in mtl_data:
                labels.append(i.month)
                labels.append(i.meter_reading)
            return render_template('user_interface/view_current_reading.html', labels = labels, values = values, items = mtl_data)


@user.route('/property/pay/bill/<string:token>')
@login_required
@property_present_active
def pay_bill(token):
    user_id = current_user.id
    prop_id = token
    mtl_data = Metertransactionlog.query.filter_by(bill_paid = False).first()
    if mtl_data is None:
        flash('All Bills Paid', 'info')
        return redirect(url_for('user.dashboard'))
    
    
    tenant_data = Tenant.query.filter_by(user_id = user_id).first()
    if tenant_data is None:
        prop_data = Property.query.filter_by(id = prop_id , owner_id = user_id).first()
        if prop_data is None or prop_data == []:
            flash('Property data not found.', 'info')
            return redirect(url_for('user.dashboard'))
        else:
            owner_data = User.query.filter_by(id = user_id).first()
            data_pre_process = mtl_data.bill_data.replace("'" , '"')
            bill = json.loads(data_pre_process)
            print_bill_data = [{
                'bill_no' : mtl_data.id,
                'date' : mtl_data.date,
                'owner_details' : [{'owner_name' : owner_data.name, 'property_name' : prop_data.building_name, 'pincode' : prop_data.pincode}],
                'tenant_details' : [{'tenant_name' : '-- NA --'}],
                'bill_details' : [bill]
            }]
            print (print_bill_data)
            return render_template('user_interface/bill_sample.html', bill_dict = print_bill_data)
    else:
        prop_data = Property.query.filter_by(tenant_id = tenant_data.id).first()
        # tenant_data = Property.query.filter_by(tenant_id = org.id).first()
        if owner_data is None or owner_data == []:
            flash('Property data not found.', 'info')
            return redirect(url_for('user.dashboard'))
        else:
            ten_data = User.query.filter_by(id = user_id).first()
            owner_data = User.query.filter_by(id = prop_data.owner_id).first()
            bill = [mtl_data.bill_data]
            print_bill_data = [{
                'bill_no' : mtl_data.id,
                'date' : mtl_data.date,
                'owner_details' : [{'owner_name' : owner_data.name, 'property_name' : prop_data.building_name, 'pincode' : prop_data.pincode}],
                'tenant_details' : [{'tenant_name' : ten_data.name}],
                'bill_details' : bill
            }]
            return render_template('user_interface/bill_sample.html', bill_dict = print_bill_data)



@user.route('/property/owned/remove/tenant/<string:token>')
@login_required
@property_present_active
def removetenant(token):
    
    user_id = current_user.id
    owner_data = User.query.filter_by(id = user_id).first()
    prop_data = Property.query.filter_by(owner_id = owner_data.id, id = token, is_active = True).first()

    # Removing the tenant
    if prop_data is None or prop_data == []:
        flash ('Property and owner details do not match. Please try later', 'danger')
        return redirect(url_for('user.displayownedproperty'))
    else:
        tenant_data = Tenant.query.filter_by(id = prop_data.tenant_id).first()
        if tenant_data is None or tenant_data == []:
            flash ('Tenant not found. Please try later', 'danger')
            return redirect(url_for('user.displayownedproperty'))
        else:
            # Fetch Tenant Mail Data
            tenant_mail_data = User.query.filter_by(id = tenant_data.user_id).first()
            
            # Making all constraints Null for Tenant
            prop_data.tenant_id = None
            prop_data.tenant_reg_confirm = False
            db.session.commit()

            prop_count = int(tenant_data.property_count)
            print ('\n\n\n Property Count : ', prop_count)
            prop_count -= 1
            print ('\n\n\n Property Count : ', prop_count)
            if prop_count > 0:
                tenant_data.property_count = prop_count
                db.session.commit()

            #If property count is 0 then delete the tenant entry
            Tenant.query.filter_by(user_id = tenant_data.user_id).delete()
            
            # Sending Remove Tenant Mail to owner and tenant
            try:
                send_owner_remove_tenant_mail(owner_data.email, prop_data.building_name)
                send_tenant_remove_tenant_mail(tenant_mail_data.email, prop_data.building_name)
            except Exception as err:
                print ('Error Logged : ', err)
                flash('Email sending failed', 'danger')
                return redirect(url_for('user.dashboard')) 
            else:
                flash ('Removed Tenant Successfully. If you wish to add a new tenant you can click on add tenant.', 'info')
                return redirect(url_for('user.displayownedproperty'))


@user.route('/property/tenant/leave/<string:token>')
@login_required
@property_present_active
def tenantleaveproperty(token):
    
    user_id = current_user.id

    # user_data stores the tenant data in the user table.
    user_data = User.query.filter_by(id = user_id).first()
    tenant_data = Tenant.query.filter_by(user_id = user_data.id).first()
    # Removing the tenant
    if tenant_data is None or tenant_data == []:
        flash ('Sorry you are not a tenant. Please try later', 'danger')
        return redirect(url_for('user.displayrentedproperty'))
    else:
        prop_data = Property.query.filter_by(tenant_id = tenant_data.id, id = token, is_active = True).first()
        if prop_data is None or prop_data == []:
            flash ('Tenant data and Property data mismatch. Please try later', 'danger')
            return redirect(url_for('user.displayrentedproperty'))
        else:
            # Fetching owners data as we need it to send a mail
            owner_data = User.query.filter_by(id = prop_data.owner_id).first()
            
            # Making all constraints Null for Tenant
            prop_data.tenant_id = None
            prop_data.tenant_reg_confirm = False
            db.session.commit()

            prop_count = int(tenant_data.property_count)
            print ('\n\n\n Property Count : ', prop_count)
            prop_count -= 1
            print ('\n\n\n Property Count : ', prop_count)
            if prop_count > 0:
                tenant_data.property_count = prop_count
                db.session.commit()

            # If property count is 0 then remove the user from the tenant category
            Tenant.query.filter_by(user_id = user_data.id).delete()
            
            # Sending Remove Tenant Mail to owner and tenant
            try:
                send_owner_leave_tenant_mail(owner_data.email, prop_data.building_name)
                send_tenant_leave_tenant_mail(user_data.email, prop_data.building_name)
            except Exception as err:
                print ('Error Logged : ', err)
                flash('Email sending failed', 'danger')
                return redirect(url_for('user.dashboard'))
            else:
                flash ('Left Property Successfuly. If you want to be added to a new property please ask your owner to add a tenant.', 'info')
                return redirect(url_for('user.displayrentedproperty'))


@user.route('/property/add/tenant/revoke/<string:token>')
@login_required
@property_present_active
def addtenantrevoke(token):
    
    user_id = current_user.id

    # user_data stores the tenant data in the user table.
    owner_data = User.query.filter_by(id = user_id).first()
    prop_data = Property.query.filter_by(owner_id = owner_data.id, id = token, is_active = True, tenant_reg_confirm = False).first()
    # Removing the tenant
    if prop_data is None or prop_data == []:
        flash ('Sorry tenant already added. Please try later', 'danger')
        return redirect(url_for('user.displayownedproperty'))
    else:
        tenant_data = Tenant.query.filter_by(user_id = owner_data.id).first()
        if tenant_data is None or tenant_data == []:
            flash ('Tenant data not present. Please try later', 'danger')
            return redirect(url_for('user.displayownedproperty'))
        else:
            # Fetching tenants mail data as we need it to send a mail
            tenant_mail_data = User.query.filter_by(id = tenant_data.user_id).first()
            
            # Making all constraints Null for Tenant
            prop_data.tenant_id = None
            db.session.commit()

            prop_count = int(tenant_data.property_count)
            
            if prop_count > 0:
                tenant_data.property_count = prop_count
                db.session.commit()

            # If property count is 0 then remove the user from the tenant category
            Tenant.query.filter_by(user_id = tenant_mail_data.id).delete()
            UserToken.query.filter_by(user_id = tenant_mail_data.user_id).delete()
            # Sending Remove Tenant Mail to owner and tenant
            send_owner_leave_tenant_mail(owner_data.email, prop_data.building_name)
            send_tenant_leave_tenant_mail(tenant_mail_data.email, prop_data.building_name)
            flash ('Revoked the entry for the tenant. If you wish to add a new tenant click on add tenant', 'info')
            return redirect(url_for('user.displayrentedproperty'))


@user.route('/property/display/ownerdetails/<string:token>' ,methods=['GET', 'POST'])
@login_required
@property_present_active
def viewownerdetails(token):
    user_id = current_user.id

    # owner_data and prop_data stores the object of the queries
    user_data = User.query.filter_by(id = user_id).first()
    tenant_data = Tenant.query.filter_by(user_id = user_data.id).first()
    if tenant_data is None or tenant_data == []:
        flash ('Sorry tenant data mismatch. Please try later', 'danger')
        return redirect(url_for('user.displayrentedproperty'))
    else:    
        prop_data = Property.query.filter_by(tenant_id = tenant_data.id, id = token, is_active = True).first()

        # Display owner details
        if prop_data is None or prop_data == []:
            flash ('Sorry owner data not found. Please try later', 'danger')
            return redirect(url_for('user.displayrentedproperty'))
        else:
            owner_data = User.query.filter_by(id = prop_data.owner_id).first()
            return render_template('user_interface/display_ownertenant_details.html', owner_data = owner_data)

@user.route('/property/display/tenantdetails/<string:token>' ,methods=['GET', 'POST'])
@login_required
@property_present_active
def viewtenantdetails(token):
    user_id = current_user.id

    # owner_data and prop_data stores the object of the queries
    owner_data = User.query.filter_by(id = user_id).first()
    prop_data = Property.query.filter_by(owner_id = owner_data.id, id = token, is_active = True, tenant_reg_confirm = True).first()
    if prop_data is None or prop_data == []:
        flash ('Sorry property and tenant data mismatch. Please try later', 'danger')
        return redirect(url_for('user.displayownedproperty'))
    else:
        user_data = Tenant.query.filter_by(id = prop_data.tenant_id).first()
        if user_data is None or user_data == []:
            flash ('Sorry tenant data mismatch. Please try later', 'danger')
            return redirect(url_for('user.displayownedproperty'))
        else:
            tenant_data = User.query.filter_by(id = user_data.user_id).first()
            return render_template('user_interface/display_ownertenant_details.html', owner_data = tenant_data)


@user.route('/support-query' ,methods=['GET', 'POST'])
def supportquery():
    form = SupportQueryForm()
    if form.validate_on_submit():
        user_id = current_user.id
        user_data = User.query.filter_by(id = user_id).first()
        if user_data is None:
            flash ('An error occured.', 'danger')
            return redirect(url_for('user.dashboard'))
        
        # -- insert the support query data
        help_type = form.prob_type.data
        prob_text = form.prob_text.data
        supp_query = Supportquery()
        supp_query.help_type = help_type
        supp_query.prob_text = prob_text
        supp_query.user_id = user_id
        db.session.add(supp_query)
        db.session.commit()

        # -- Fetch the query to send a mail
        supp_data = Supportquery.query.filter_by(user_id = user_id, help_type = help_type, prob_text = prob_text).first()
        if supp_data is None:
            flash ('Query register but data not found.', 'danger')
            return redirect(url_for('user.dashboard'))
        ticket_id = supp_data.id
        try:
            send_support_query_mail(user_data.email, ticket_id)
        except Exception as err:
            print ('Error Logged : ', err)
            flash('Email sending failed', 'danger')
            return redirect(url_for('user.dashboard'))
        else:
            flash ('Your Problem has been successfully registered.', 'info')
            return redirect(url_for('user.dashboard'))
    return render_template('user_interface/support_query.html', form = form)

'''

@user.route('/profile/edit', methods=['GET', 'POST'])
@login_required
@public_key_required
def profile_edit():
    form = ProfileUpdateForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.phone_number = form.phone_number.data
        password = form.password.data
        if password:
            current_user.password = User.hash_password(password)
        if form.logo.data:
            logo_name = save_logo(form.logo.data)
            current_user.logo = logo_name
        db.session.commit()
        if current_logo_name:
            delete_logo(current_logo_name)
        flash('Your profile is successfully updated', 'success')
        return redirect(url_for('.profile'))
    else:
        form.name.data = current_user.name
        form.phone_number.data = current_user.phone_number
        form.public_key.data = current_user.public_key
    return render_template('organizations/profile_edit.html',
                           org=current_user, form=form)


'''
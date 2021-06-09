import os
from functools import wraps
from secrets import token_hex
from iot_security.models import User, UserToken, Property, Tenant
from flask import redirect, url_for, render_template, current_app, flash
from flask_login import current_user
from flask_mail import Message
from iot_security import mail
from hashlib import md5
from datetime import datetime
from PIL import Image



def send_confirmation_mail(reciever_email, link):
    html_message = render_template('emails/email_confirmation.html', link=link)
    text_message = render_template('emails/email_confirmation.txt', link=link)
    msg = Message('Email Activation link', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_reset_password_mail(reciever_email, link):
    html_message = render_template(
        'emails/reset_password_link.html', link=link)
    text_message = render_template('emails/reset_password_link.txt', link=link)
    msg = Message('Reset password link', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_login_email_mail(reciever_email, link):
    html_message = render_template(
        'emails/login_email_link.html', link=link)
    text_message = render_template('emails/login_email_link.txt', link=link)
    msg = Message('Login Email Link', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)

def property_present_active(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user_id = current_user.id
        tenant_data = Tenant.query.filter_by(user_id = user_id).first()
        if tenant_data is None:
            property_data = Property.query.filter((Property.owner_id == user_id) | (Property.tenant_id == user_id)).all()
            if property_data is None or property_data == []:
                return redirect (url_for('user.propertymanagement'))
            for main_data in property_data:
                print (main_data)
                if main_data.is_active == True:
                    return func(*args, **kwargs)
            return redirect (url_for('user.propertymanagement'))
        else:
            property_data = Property.query.filter((Property.owner_id == user_id) | (Property.tenant_id == tenant_data.id)).all()
            if property_data is None or property_data == []:
                return redirect (url_for('user.propertymanagement'))
            for main_data in property_data:
                print (main_data)
                if main_data.is_active == True:
                    return func(*args, **kwargs)
            return redirect (url_for('user.propertymanagement'))

    return decorated_function


def property_management_disable(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        user_id = current_user.id
        tenant_data = Tenant.query.filter_by(user_id = user_id).first()
        print ('\n\n\n\n',tenant_data)
        if tenant_data is None:
            property_data = Property.query.filter((Property.owner_id == user_id) | (Property.tenant_id == user_id)).first()
            if property_data is None or property_data == []:
                return func(*args, **kwargs)
            else:
                if property_data.is_active == True:
                    return redirect (url_for('user.dashboard'))
                else:
                    return func(*args, **kwargs)
            return func(*args, **kwargs)
        else:
            property_data = Property.query.filter((Property.owner_id == user_id) | (Property.tenant_id == tenant_data.id)).first()
            ('\n\n\n\n',property_data)
            if property_data is None or property_data == []:
                return func(*args, **kwargs)
            else:
                if property_data.is_active == True:
                    return redirect (url_for('user.dashboard'))
                else:
                    return func(*args, **kwargs)
            return func(*args, **kwargs)
    return decorated_function


def send_tenant_approval_check_mail(reciever_email, link):
    html_message = render_template(
        'emails/tenant_approval_link.html', link=link)
    text_message = render_template('emails/tenant_approval_link.txt', link=link)
    msg = Message('Tenant Approval Mail', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_tenantapproval_mail(reciever_email):
    html_message = render_template('emails/email_userapproval.html', link='Congratulations. Your property has been approved.')
    text_message = render_template('emails/email_userapproval.txt', link='Congratulations. Your property has been approved.')
    msg = Message('Account Activated', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)

def send_ownerapproval_mail(reciever_email):
    html_message = render_template('emails/email_userapproval.html', link='Congratulations. Your tenant has approved the property confirmation.')
    text_message = render_template('emails/email_userapproval.txt', link='Congratulations. Your tenant has approved the property confirmation.')
    msg = Message('Account Activated', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_ownerreject_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='Sorry. Your Tenant has rejected the property confirmation.')
    text_message = render_template('emails/email_userreject.txt', link='Sorry. Your Tenant has rejected the property confirmation..')
    msg = Message('Property Rejected', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)

def send_tenantreject_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='You have successfully rejected the property confirmation.')
    text_message = render_template('emails/email_userreject.txt', link='You have successfully rejected the property confirmation.')
    msg = Message('Property Rejected', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_owner_remove_tenant_mail(reciever_email, prop_name):
    html_message = render_template('emails/email_userreject.html', link='You have successfully removed the tenant from your property named : {}. If you wish to add him back you can go to the add tenant option.'.format(prop_name))
    text_message = render_template('emails/email_userreject.txt', link='You have successfully removed the tenant from your property named : {}. If you wish to add him back you can go to the add tenant option.'.format(prop_name))
    msg = Message('Tenant Removed', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)
            

def send_tenant_remove_tenant_mail(reciever_email, prop_name):
    html_message = render_template('emails/email_userreject.html', link='You have been removed from the property named {}. If there is a problem please contact your owner'.format(prop_name))
    text_message = render_template('emails/email_userreject.txt', link='You have been removed from the property named {}. If there is a problem please contact your owner'.format(prop_name))
    msg = Message('Tenant Removed', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_owner_leave_tenant_mail(reciever_email, prop_name):
    html_message = render_template('emails/email_userreject.html', link='Tenant has left from your property named : {}. If you wish to add him back you can go to the add tenant option.'.format(prop_name))
    text_message = render_template('emails/email_userreject.txt', link='Tenant has left from your property named : {}. If you wish to add him back you can go to the add tenant option.'.format(prop_name))
    msg = Message('Tenant Left', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)
            
            
def send_tenant_leave_tenant_mail(reciever_email, prop_name):
    html_message = render_template('emails/email_userreject.html', link='You have successfully left  the property named {}. If there is a problem please contact your owner'.format(prop_name))
    text_message = render_template('emails/email_userreject.txt', link='You have successfully left the property named {}. If there is a problem please contact your owner'.format(prop_name))
    msg = Message('Tenant Left', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_support_query_mail(reciever_email, ticket_id):
    html_message = render_template('emails/email_userreject.html', link='You have successfully registered your query with Ticket Id {}. Please use the same ID for further communication. The Support Team will get back to you shortly'.format(ticket_id))
    text_message = render_template('emails/email_userreject.txt', link='You have successfully registered your query with Ticket Id {}. Please use the same ID for further communication. The Support Team will get back to you shortly'.format(ticket_id))
    msg = Message('Support Ticket Raised', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)
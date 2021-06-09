import os
from functools import wraps
from secrets import token_hex
from iot_security.models import Productactivation, User, Admin
from flask import redirect, url_for, render_template, current_app, flash
from flask_login import current_user
from flask_mail import Message
from iot_security import mail
from hashlib import md5
from datetime import datetime
from PIL import Image


def key_created(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        org = Productactivation.query.first()
        if org is None or org == []:
            flash ('Please enter license key to activate product', 'danger')
            return redirect(url_for('admin.activate'))
        return func(*args, **kwargs)
    return decorated_function


def super_user(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        org = Admin.query.filter_by(id = current_user.id).first()
        if org is None or org == []:
            flash ('Something went wrong.', 'danger')
            return redirect(url_for('admin.dashboard'))
        print(org.role)
        if org.role == 'admin':
            flash ('Access Denied.', 'danger')
            return redirect(url_for('admin.dashboard'))
        return func(*args, **kwargs)
    return decorated_function

def key_activated(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        org = Productactivation.query.first()
        if org is None or org == []:
            flash('Product key unavailable.', 'danger')
            return redirect(url_for('admin.activate'))
        else:
            if org.activated == True:
                flash('System is already activated.', 'danger')
                return redirect(url_for('admin.login'))
            else:
                flash('Product not yet activated.', 'danger')
                return redirect(url_for('admin.activate'))
        return func(*args, **kwargs)
    return decorated_function



def key_not_activated(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        org = Productactivation.query.first()
        if org is None or org == []:
            return redirect(url_for('admin.activate'))
        else:
            if org.activated == True:
                flash('System is already activated.', 'danger')
                return redirect(url_for('admin.login'))
        return func(*args, **kwargs)
    return decorated_function


def no_admin(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.first()
        if admin is None or admin == []:
            return redirect(url_for('admin.registration'))
        return func(*args, **kwargs)
    return decorated_function



def send_confirmation_mail(reciever_email, link):
    html_message = render_template('emails/email_confirmation.html', link=link)
    text_message = render_template('emails/email_confirmation.txt', link=link)
    msg = Message('Email Activation link', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)

def send_registration_mail(reciever_email, link):
    html_message = render_template('emails/registration_confirmation.html', link=link)
    text_message = render_template('emails/registration_confirmation.txt', link=link)
    msg = Message('Create account link', recipients=[reciever_email])
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


def send_userapproval_mail(reciever_email):
    html_message = render_template('emails/email_userapproval.html', link='Congratulations. Your property has been approved.')
    text_message = render_template('emails/email_userapproval.txt', link='Congratulations. Your property has been approved.')
    msg = Message('Account Activated', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_userreject_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='Sorry. The System administrator has rejected your property for AuthElectric. You can try to register a new property again with valid information. In case of any quries feel free to contact us.')
    text_message = render_template('emails/email_userreject.txt', link='Sorry. The System administrator has rejected your property for AuthElectric. You can try to register a new property again with valid information. In case of any quries feel free to contact us.')
    msg = Message('Account Rejected', recipients=[reciever_email])
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


def send_key_activation_mail(reciever_email, key):
    html_message = render_template(
        'emails/key_activation.html', key=key)
    text_message = render_template('emails/key_activation.txt', key=key)
    msg = Message('Product Key Activation', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)



def send_support_query_completed_mail(reciever_email, ticket_id):
    html_message = render_template('emails/email_userreject.html', link='Your problem with Ticket ID {} has been successfully resolved. This query is being closed by the admin'.format(ticket_id))
    text_message = render_template('emails/email_userreject.txt', link='Your problem with Ticket ID {} has been successfully resolved. This query is being closed by the admin'.format(ticket_id))
    msg = Message('Support Query Solved', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_support_query_pending_mail(reciever_email, ticket_id):
    html_message = render_template('emails/email_userreject.html', link='Admin has just acknowledges you query with Ticket Id {}. The Support Team will get back to you shortly'.format(ticket_id))
    text_message = render_template('emails/email_userreject.txt', link='Admin has just acknowledges you query with Ticket Id {}. The Support Team will get back to you shortly'.format(ticket_id))
    msg = Message('Support Query Acknowledged', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def remove_duplicate_iot_server(x):
      return list(dict.fromkeys(x))
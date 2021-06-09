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






def send_inactive_meter_tenant_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='Billing request failed for your meter. It will be conducted again in the next 7 days. If it fails to do so your meter will be deactivated.')
    text_message = render_template('emails/email_userreject.txt', link='Billing request failed for your meter. It will be conducted again in the next 7 days. If it fails to do so your meter will be deactivated.')
    msg = Message('Inactive Meter Tenant', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_inactive_meter_owner_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='Billing request failed for your meter. It will be conducted again in the next 7 days. If it fails to do so your meter will be deactivated.')
    text_message = render_template('emails/email_userreject.txt', link='Billing request failed for your meter. It will be conducted again in the next 7 days. If it fails to do so your meter will be deactivated.')
    msg = Message('Inactive Meter Owner', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)

def send_disabled_meter_tenant_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='The second request was made for your electricity meter and it was found inactive. Thus your accound has been disabled. Contact the admin for more information.')
    text_message = render_template('emails/email_userreject.txt', link='The second request was made for your electricity meter and it was found inactive. Thus your accound has been disabled. Contact the admin for more information.')
    msg = Message('Disabled Meter Tenant', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_disabled_meter_owner_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='The second request was made for your electricity meter and it was found inactive. Thus your accound has been disabled. Contact the admin for more information.')
    text_message = render_template('emails/email_userreject.txt', link='The second request was made for your electricity meter and it was found inactive. Thus your accound has been disabled. Contact the admin for more information.')
    msg = Message('Disabled Meter Owner', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_bill_tenant_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='Your bill for the month is successfully generated. Please check your dashboard')
    text_message = render_template('emails/email_userreject.txt', link='Your bill for the month is successfully generated. Please check your dashboard')
    msg = Message('New Bill', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)


def send_bill_owner_mail(reciever_email):
    html_message = render_template('emails/email_userreject.html', link='Your bill for the month is successfully generated. Please check your dashboard')
    text_message = render_template('emails/email_userreject.txt', link='Your bill for the month is successfully generated. Please check your dashboard')
    msg = Message('New Bill', recipients=[reciever_email])
    msg.body = text_message
    msg.html = html_message
    mail.send(msg)
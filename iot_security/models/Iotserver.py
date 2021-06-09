from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from iot_security import db
from secrets import token_urlsafe

class Iotserver(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    server_reg_name = db.Column(db.String(255), nullable = False, unique = True)
    pincode = db.Column(db.String(255), nullable = False)
    area = db.Column(db.String(255), nullable=False)
    device_count = db.Column(db.Integer, nullable = True)
    pubkey = db.Column(db.String(255), unique=True)
    is_active = db.Column(db.Boolean, nullable = False, default=False)
    server_reg_confirm = db.Column(db.Boolean, nullable = False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    remote_ip = db.Column(db.String(255), nullable=True)
    users = db.relationship("Property", backref="iotserver", lazy='dynamic')
    devices = db.relationship('Iotdevice',backref='iotserver',lazy='dynamic')
    api_key = db.Column(db.String(255), nullable=False, unique= True)
    key = db.Column(db.String(255), nullable=True, unique= True)
    sent_at = db.Column(db.DateTime, nullable=True)
    valid_sec = db.Column(db.Integer, nullable=True)
    
    def __str__(self):
        return 'Server:{}'.format(self.name)


    # Generate API_Key
    @staticmethod
    def generate_api_key():
        token = token_urlsafe(64)                               # urlsafe to generate key
        while Iotserver.query.filter_by(api_key=token).first():
            token = token_urlsafe(64)                           # Incase Key already exists, regenrate
        return token
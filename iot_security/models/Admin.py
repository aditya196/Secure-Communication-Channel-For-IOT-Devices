from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from iot_security import db


class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    name = db.Column(db.String(255), nullable = True)
    username = db.Column(db.String(255), nullable = True, unique=True)
    employee_id = db.Column(db.String(255), nullable = True, unique=True)
    email = db.Column(db.String(255), nullable = True)
    phone_number = db.Column(db.String(255), nullable = True, unique=True)
    password = db.Column(db.String(255), nullable = True)
    email_verified = db.Column(db.Boolean, nullable = True, default=False)
    is_active = db.Column(db.Boolean, nullable = True, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=True)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    role = db.Column(db.String(255), nullable = True, unique=False)
    tokens = db.relationship('AdminToken',backref='admin',lazy=True)

    def __str__(self):
        return 'Admin:{}'.format(self.name)

    @staticmethod
    def hash_password(password):
        return generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password,password)
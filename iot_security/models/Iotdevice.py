from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from iot_security import db


class Iotdevice(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    device_reg_name = db.Column(db.String(255), nullable = False, unique = True)
    address = db.Column(db.String(255), nullable=False)
    pubkey = db.Column(db.String(255), nullable = True, unique=True)
    previous_meter_readings = db.Column(db.Integer, nullable=True)
    current_meter_readings = db.Column(db.Integer, nullable=True)
    is_active = db.Column(db.Boolean, nullable = False, default=False)
    housing_property = db.Column(db.Boolean, nullable = True)
    property_assigned_status = db.Column(db.Boolean, nullable = False, default=False)
    device_reg_confirm = db.Column(db.Boolean, nullable = False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    server_id =  db.Column(db.Integer, db.ForeignKey('iotserver.id'), nullable=True)
    property_id = db.relationship('Property', backref='iotdevice',uselist=False, lazy=True)
    
    
    
    def __str__(self):
        return 'Device:{}'.format(self.name)

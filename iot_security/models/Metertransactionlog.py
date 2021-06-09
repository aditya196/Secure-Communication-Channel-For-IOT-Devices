from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from iot_security import db


class Metertransactionlog(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    month = db.Column(db.String(255), nullable = False)
    year = db.Column(db.String(255), nullable = False)
    date = db.Column(db.String(255), nullable = False)
    bill_ammount = db.Column(db.Float, nullable=False)
    bill_paid = db.Column(db.Boolean(255),default=False)
    unit_cost = db.Column(db.Float, nullable=False)
    penalty_added = db.Column(db.Float, nullable=False)
    meter_reading = db.Column(db.Integer, nullable=False)
    monthly_units = db.Column(db.Integer, nullable=False)
    bill_data = db.Column(db.Text, nullable = False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # -- Foreign key
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=True)

    
 
    
    def __str__(self):
        return 'Server:{}'.format(self.id)

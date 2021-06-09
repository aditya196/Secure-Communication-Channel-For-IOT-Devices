from datetime import datetime
from flask_login import UserMixin
from iot_security import db


class Tax(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    tax_name = db.Column(db.String(255), nullable=True, unique=True)
    tax_rate = db.Column(db.String(255),nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    def __str__(self):
        return 'Server:{}'.format(self.tax_name)

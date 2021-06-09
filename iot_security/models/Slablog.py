from datetime import datetime
from flask_login import UserMixin
from iot_security import db


class Slablog(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    lower_slab = db.Column(db.String(255), nullable=False)
    upper_slab = db.Column(db.String(255), nullable=True)
    housing = db.Column(db.String(255), nullable=False)
    commercial = db.Column(db.String(255), nullable=False)
    penalty = db.Column(db.String(255),default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    def __str__(self):
        return 'Server:{}'.format(self.id)

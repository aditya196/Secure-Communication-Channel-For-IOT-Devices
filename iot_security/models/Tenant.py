from datetime import datetime
from flask_login import UserMixin
from iot_security import db

class Tenant(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    property_count = db.Column(db.Integer, default=0, nullable = False)
    # -- Backrefrences for other tables
    property_id = db.relationship('Property',backref='tenant',lazy=True)
    

    def __str__(self):
        return 'Tenant: {}'.format(self.id)

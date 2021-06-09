from datetime import datetime
from flask_login import UserMixin
from iot_security import db

class Billrequestpaymentdefaulters(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    

    def __str__(self):
        return 'Billrequestdefaulters: {}'.format(self.id)
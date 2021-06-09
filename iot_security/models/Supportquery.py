from datetime import datetime
from flask_login import UserMixin
from iot_security import db


class Supportquery(db.Model, UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    help_type = db.Column(db.String(255), nullable=True)
    status = db.Column(db.Boolean, nullable = False, default = False)
    prob_text = db.Column(db.Text, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    def __str__(self):
        return 'Query :{}'.format(self.id)
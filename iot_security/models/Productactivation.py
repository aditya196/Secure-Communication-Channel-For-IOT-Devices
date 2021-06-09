from datetime import datetime, timedelta
import math,random
from werkzeug.security import generate_password_hash, check_password_hash
from iot_security.models.utils import rand_pass
from flask_login import UserMixin
from iot_security import db
from iot_security import login_manager


class Productactivation(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    product_key = db.Column(db.String(255), nullable=False)
    activated = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) 
    
    def __str__(self):
        return 'Product: {}'.format(self.product_key)


    @staticmethod
    def generate_key():
        activation_key = rand_pass(16)
        print ('Product key :', activation_key)
        org = Productactivation()
        org.product_key = activation_key
        db.session.add(org)
        db.session.commit()
        return activation_key

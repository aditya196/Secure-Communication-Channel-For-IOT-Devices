from datetime import datetime
from iot_security import db
from secrets import token_urlsafe

class City(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    state = db.Column(db.String(255), nullable = False)
    city = db.Column(db.String(255), nullable = False)

    def __str__(self):
        return 'City:{}'.format(self.id)
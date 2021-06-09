from datetime import datetime, timedelta
from secrets import token_urlsafe
from iot_security import db


class AdminToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(), nullable=False)
    token_type = db.Column(db.String(), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow , nullable=False)
    valid_sec = db.Column(db.Integer, nullable=False)
    db.UniqueConstraint('token_type', 'token', name='admin_token_token_type_token_key')


    # Generate a token 
    @staticmethod
    def generate_token(token_type, admin_id, valid_sec):
        token = token_urlsafe(64)                              # urlsafe to generate token
        while AdminToken.query.filter_by(token=token, token_type=token_type).first():
            token = token_urlsafe(64)                          # incase token already exists, regenrate it
        admin_token = AdminToken.query.filter_by(admin_id=admin_id).first()
        if admin_token is None or admin_token == []:
            new_admin_token = AdminToken()
            new_admin_token.admin_id = admin_id
            new_admin_token.token = token
            new_admin_token.token_type = token_type
            new_admin_token.valid_sec = valid_sec
            db.session.add(new_admin_token)
            db.session.commit()
            return new_admin_token
        else:
            admin_token.token = token
            admin_token.token_type = token_type
            admin_token.valid_sec = valid_sec
            db.session.commit()
            return admin_token

    # Check whether token is still valid
    def is_valid(self):
        valid_till = self.sent_at + timedelta(seconds=self.valid_sec)
        return valid_till > datetime.utcnow()
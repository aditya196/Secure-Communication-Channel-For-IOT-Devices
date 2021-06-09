from datetime import datetime, timedelta
from secrets import token_urlsafe
from iot_security import db


class UserToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(), nullable=False)
    token_type = db.Column(db.String(), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey(
        'user.id'), nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    valid_sec = db.Column(db.Integer, nullable=False)
    db.UniqueConstraint('token_type', 'token', name='user_token_token_type_token_key')

    @staticmethod
    def generate_token(token_type, user_id, valid_sec):
        token = token_urlsafe(64)                              # urlsafe to generate token
        while UserToken.query.filter_by(token=token, token_type=token_type).first():
            token = token_urlsafe(64)                          # incase token already exists, regenrate it
        user_token = UserToken.query.filter_by(user_id=user_id).first()
        if user_token is None or user_token == []:
            new_user_token = UserToken()
            new_user_token.user_id = user_id
            new_user_token.token = token
            new_user_token.token_type = token_type
            new_user_token.valid_sec = valid_sec
            db.session.add(new_user_token)
            db.session.commit()
            return new_user_token
        else:
            user_token.token = token
            user_token.token_type = token_type
            user_token.valid_sec = valid_sec
            db.session.commit()
            return user_token

    def is_valid(self):
        valid_till = self.sent_at + timedelta(seconds=self.valid_sec)
        return valid_till > datetime.utcnow()
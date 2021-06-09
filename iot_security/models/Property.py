from datetime import datetime
from flask_login import UserMixin
from iot_security import db
from secrets import token_urlsafe

class Property(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    flat_no = db.Column(db.String(500), nullable=False)
    building_name = db.Column(db.String(500), nullable=False)
    state = db.Column(db.String(500), nullable=False)
    pincode = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(255), nullable=False)
    street = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=False, nullable=False)
    bill_gen_status = db.Column(db.Boolean, default=False, nullable=False)
    tenant_reg_confirm = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    # -- Foreign Keys from other tables
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tenant_id = db.Column(db.Integer, db.ForeignKey('tenant.id'), nullable=True)
    server_id = db.Column(db.Integer, db.ForeignKey('iotserver.id'), nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey('iotdevice.id'), nullable=True)
    
    # -- Reference to the foreign key to other table
    meter_trans_id = db.relationship('Metertransactionlog',backref='property',lazy=True)
    bill_req_defaulter_id = db.relationship('Billrequestdefaulters',backref='property',lazy=True)
    bill_req_payment_defaulter_id = db.relationship('Billrequestpaymentdefaulters',backref='property',lazy=True)
    def __str__(self):
        return 'Property: {}'.format(self.id)
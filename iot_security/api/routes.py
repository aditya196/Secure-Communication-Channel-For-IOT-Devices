from functools import wraps
from flask import Blueprint, render_template, redirect, url_for, flash, jsonify, request
from flask_login import login_user, current_user, login_required, logout_user
from iot_security.models import (Admin , 
                                AdminToken, 
                                User, 
                                UserToken, 
                                Iotserver, 
                                Iotdevice, 
                                Productactivation, 
                                Property, 
                                Slablog, 
                                Tax, 
                                Metertransactionlog, 
                                City, 
                                Miscellaneous,
                                Supportquery,
                                Billrequestdefaulters,
                                Tenant)
from iot_security import db
from iot_security import limiter
from iot_security.auth.token_timestamp import generate_adjusted_timestamp
import requests
import hashlib
import json
import datetime
from iot_security.auth.ECDH import *
from iot_security.api.utils import (send_inactive_meter_owner_mail,
                                    send_inactive_meter_tenant_mail,
                                    send_disabled_meter_owner_mail,
                                    send_disabled_meter_tenant_mail,
                                    send_bill_owner_mail,
                                    send_bill_tenant_mail)
from iot_security.auth.utils import encrypt_msg, decrypt_msg, encrypt_key, clean_key, decrypt_key, verify_signature
import base64
from iot_security.auth.billing import main_billing, late_billing
from requests.exceptions import HTTPError
from base64 import b64encode
from base64 import b64decode

api = Blueprint('api', __name__)


def gen_bill(bill_units, server_id):
    active = {}
    inactive = {}
    for k,v in bill_units.items():
        print (v)
        if v == None:
            print ('None :', v)
            inactive[int(k)] = v
            continue
        active[int(k)] = int(v)
    print(active)
    print (inactive)
    active_result = active_meters(active, server_id)
    inactive_result = inactive_meters(inactive, server_id)
    return 'MTL Updated'


def active_meters(active,server_id):
    if isinstance(active, dict):
        for k,v in active.items():
            prop_data = Property.query.filter_by(device_id = k , bill_gen_status = False).first()
            if prop_data is None:
                print ('here')
                continue
            bill_req_def_data = Billrequestdefaulters.query.filter_by(property_id = prop_data.id).first()
            device_data = Iotdevice.query.filter_by(id = prop_data.device_id).first()
            server_data = Iotserver.query.filter_by(id = prop_data.server_id).first()
            pre_reading = int(device_data.previous_meter_readings)
            cur_reading = int(device_data.current_meter_readings)
            
            mydate = datetime.datetime.now()
            month_name = mydate.strftime("%B")
            year = mydate.strftime("%Y")
            date = mydate.strftime("%D")
            mtl_meter_reading = int(v)
            if pre_reading == 0:
                device_data.previous_meter_readings = int(v)
                device_data.current_meter_readings = int(v)
                db.session.commit()
                units = v
            else:
                device_data.previous_meter_readings = cur_reading
                device_data.current_meter_readings = v
                units = v - cur_reading
                db.session.commit()
            print ('units : ', units)
            
            if bill_req_def_data is None:
                bill_val = main_billing(int(units) , device_data.housing_property)
                print(bill_val)
                # -- Fetching Bill values
                for k,v in bill_val.items():
                    if k == 'slab_cost':
                        for k1 in v:
                            for k2,v2 in k1.items():
                                if k2 == 'units':
                                    meter_units = v2
                                if k2 == 'slab_cost':
                                    sl_cost = v2
                                    
                                continue
                    elif k == 'total':
                        total_amt = float(v)
                        continue
                
                prop_data.bill_gen_status = True
                db.session.commit()
                # -- Adding Billing data To Meter Transaction Log
                mtl = Metertransactionlog()
                mtl.month = month_name
                mtl.year = year
                mtl.date = date
                mtl.bill_ammount = total_amt
                mtl.bill_paid = False
                mtl.unit_cost = float(sl_cost)
                mtl.penalty_added = 0
                mtl.meter_reading = mtl_meter_reading
                mtl.bill_data = str(bill_val)
                mtl.monthly_units = meter_units
                mtl.property_id = prop_data.id
                db.session.add(mtl)
                db.session.commit()
                continue
            else:
                
                print ('units : ', units)
                bill_val = late_billing(int(units) , device_data.housing_property)
                print(bill_val)

                # -- Fetching Bill values
                for k,v in bill_val.items():
                    if k == 'slab_cost':
                        for k1 in v:
                            for k2,v2 in k1.items():
                                if k2 == 'units':
                                    meter_units = v2
                                if k2 == 'slab_cost':
                                    sl_cost = v2
                                if k2 == 'penalty':
                                    penalty = v2
                                continue
                    elif k == 'total':
                        total_amt = float(v)
                        continue
                prop_data.bill_gen_status = True
                Billrequestdefaulters.query.filter_by(property_id = prop_data.id).delete()
                db.session.commit()
                # -- Adding Billing data To Meter Transaction Log
                mtl = Metertransactionlog()
                mtl.month = month_name
                mtl.year = year
                mtl.date = date
                mtl.bill_ammount = total_amt
                mtl.bill_paid = False
                mtl.unit_cost = float(sl_cost)
                mtl.meter_reading = mtl_meter_reading
                mtl.monthly_units = meter_units
                mtl.bill_data = str(bill_val)
                mtl.penalty_added = float(penalty)
                mtl.property_id = prop_data.id
                db.session.add(mtl)
                db.session.commit()
                continue

            
            # -- Sending respective mails
        owner_data = User.query.filter_by(id = prop_data.owner_id).first()
        if prop_data.tenant_reg_confirm:
            tenant_data = Tenant.query.filter_by(id = prop_data.id).first()
            tenant_mail_data = User.query.filter_by(id = tenant_data.user_id).first()
            send_bill_tenant_mail(tenant_mail_data.email)
        send_bill_owner_mail(owner_data.email)
    else:
        pass
    # make server_id true here


def inactive_meters(inactive,server_id):
    if isinstance(inactive, dict):
        for k,v in inactive.items():
            prop_data = Property.query.filter_by(device_id = k , bill_gen_status = False).first()
            if prop_data is None:
                continue
            bill_req_def_data = Billrequestdefaulters.query.filter_by(property_id = prop_data.id).first()
            if bill_req_def_data is None:
                prop_data.bill_gen_status = False
                db.session.commit()
                bill_req_add_data = Billrequestdefaulters()
                bill_req_add_data.property_id = prop_data.id
                db.session.add(bill_req_add_data)
                db.session.commit()
                owner_data = User.query.filter_by(id = prop_data.owner_id).first()
                if prop_data.tenant_reg_confirm:
                    tenant_data = Tenant.query.filter_by(id = prop_data.id).first()
                    tenant_mail_data = User.query.filter_by(id = tenant_data.user_id).first()
                    send_inactive_meter_tenant_mail(tenant_mail_data.email)
                send_inactive_meter_owner_mail(owner_data.email)
                continue
            else:
                device_data = Iotdevice.query.filter_by(id = prop_data.device_id).first()
                server_data = Iotserver.query.filter_by(id = prop_data.server_id).first()
                prop_data.is_active = False
                device_data.is_active = False
                Billrequestdefaulters.query.filter_by(property_id = prop_data.id).delete()
                db.session.commit()
                data = {
                    "device_id" : device_data.id
                }
                base_url = 'http://{}:5001/api/v1/iot_server/deactivate/device'.format(server_data.remote_ip)
                try:
                    req_url = requests.post(url = base_url, json = data)
                    req_url.raise_for_status()
                    continue
                except HTTPError as http_err:
                    continue
                except Exception as err:
                    continue
                owner_data = User.query.filter_by(id = prop_data.owner_id).first()
                if prop_data.tenant_reg_confirm:
                    tenant_data = Tenant.query.filter_by(id = prop_data.id).first()
                    tenant_mail_data = User.query.filter_by(id = tenant_data.user_id).first()
                    send_disabled_meter_tenant_mail(tenant_mail_data.email)
                send_disabled_meter_owner_mail(owner_data.email)
        print('task completed')

    return 'Task Completed - Inactive'        
    # make ser_id true here

@api.route('/v1/iot_server/check_seed', methods=['POST'])
@limiter.exempt
def iot_server_seed():
    remote_ip_addr = request.remote_addr
    content = request.get_json()
    seed_1 = content.get('seed_1')
    seed_2 = content.get('seed_2')
    id = content.get('id')

    if id == None and seed_1 == None and seed_2 == None:
        return jsonify({
                    'status': '200',
                    'data': 'Invalid Message Format'
                    })

    else:
        server_data = Iotserver.query.filter_by(id=id).first()
        if server_data == [] or server_data is None:
            return jsonify({
                    'status': '200',
                    'data': 'Invalid ID'
                    })
        else:
            API_KEY = server_data.api_key
            t1 , t2 = generate_adjusted_timestamp()
            t1 = str(t1)
            t2 = str(t2)
            API_KEY = str(API_KEY)
            data_1 = API_KEY+t1
            print ('data_1 : ', data_1)
            data_1 = hashlib.sha256(data_1.encode())
            data_1 = data_1.hexdigest()
            # Generating Seed Value to send to client
            data_2 = API_KEY+t2
            print ('data_2 : ', data_2)
            data_2 = hashlib.sha256(data_2.encode())
            data_2 = data_2.hexdigest()
            print('data 1 :', data_1)
            print('data 2 :', data_2)
            print('seed 2 :', seed_1)
            print('seed 2 :', seed_2)
            if seed_1 == data_1 or seed_2 == data_2:
                server_data.remote_ip = remote_ip_addr
                db.session.commit()
                return jsonify({
                    'status': '200',
                    'data': 'ALL_OK'
                    })
            else:
                return jsonify({
                    'status': '200',
                    'data': 'Token Expired'
                    })



@api.route('/v1/iot_server/registration', methods=['POST'])
@limiter.exempt
def iot_server_registration_api():
    remote_ip_addr = request.remote_addr
    content = request.get_json()
    client_publickey = content.get('iot_server_publickey')
    ecdsa_signature = content.get('signature')
    ecdsa_public_key = content.get('public_key')
    id = content.get('id')

    if id == None and client_publickey == None and ecdsa_public_key == None and ecdsa_signature == None:
        return jsonify({
                    'status': '200',
                    'message': 'Invalid Message Format'
                    })

    else:
        ecdsa_message_raw_encoded = client_publickey.encode()
        ecdsa_message_generation = hashlib.sha256(ecdsa_message_raw_encoded)
        ecdsa_message_generation_encoded = ecdsa_message_generation.hexdigest()
        ecdsa_signature = b64decode(ecdsa_signature)

        verified_sig = verify_signature(ecdsa_public_key,ecdsa_message_generation_encoded,ecdsa_signature)
        if verified_sig == False:
            return jsonify({
                    'status': '200',
                    'message': 'Bad Request'
                    })
        else:  
            server_data = Iotserver.query.filter_by(id=id, remote_ip=remote_ip_addr).first()
            if server_data == [] or server_data is None:
                return jsonify({
                        'status': '200',
                        'message': 'Bad Request'
                        })
            else:
                print(client_publickey)
                print(type(client_publickey))
                client_publickey = tuple(map(int, client_publickey.split(', ')))
                # -- Generate public private key paid
                server_privateKey, server_publickey = make_keypair()
                server_privateKey = clean_key(server_privateKey)
                server_privateKey = int(server_privateKey)
                server_publickey = clean_key(server_publickey)
                # -- generate shared secreti.t aes256 bit key
                shared_secret = scalar_mult(server_privateKey,client_publickey)
                shared_secret = str(shared_secret)
                m = hashlib.sha256(shared_secret.encode())
                server_publickey = str(server_publickey) 
                # m = base64.b64encode(m)
                aes_key = m.hexdigest()
                aes_key = aes_key[0:32]
                aes_key = aes_key.encode()

                msg = {
                    "id" : server_data.id,
                    "server_reg_name" : server_data.server_reg_name,
                    "pincode" : server_data.pincode,
                    "area" : server_data.area,
                    }
                msg = json.dumps(msg)
                ct = encrypt_msg(msg,aes_key)
                print(ct)
                ciphertext = ct[0]
                iv = ct[1]
                aes_key = aes_key.decode()
                encrypted_key = encrypt_key(aes_key)
                decrypted_key = decrypt_key(encrypted_key)
                server_data.key = encrypted_key
                server_data.pubkey = ecdsa_public_key 
                server_data.is_active = True
                db.session.commit()
                return jsonify({
                                'status': '200',
                                'message' : 'success',
                                'cipher_text' : ciphertext,
                                'iv' : iv,
                                'server_public_key' : server_publickey
                                })



@api.route('/v1/iot_server/registration_confirm', methods=['POST'])
@limiter.exempt
def iot_server_registration_confirm_api():
    remote_ip_addr = request.remote_addr
    content = request.get_json()
    ciphertext = content.get('ciphertext')
    iv = content.get('iv')
    ecdsa_signature_registration_confirm = content.get('signature') 
    # print(' pehele iv :', iv)
    # print(' pehele ciphertext :', ciphertext)
    if iv == None and ciphertext == None and ecdsa_signature_registration_confirm == None:
        return jsonify({
                    'status': '200',
                    'message': 'Invalid Message Format'
                    })

    else:
        server_data = Iotserver.query.filter_by(remote_ip=remote_ip_addr, is_active = True).first()
        ecdsa_message_raw_encoded = ciphertext.encode()
        ecdsa_message_generation = hashlib.sha256(ecdsa_message_raw_encoded)
        ecdsa_message_generation_encoded = ecdsa_message_generation.hexdigest()
        ecdsa_signature = b64decode(ecdsa_signature_registration_confirm)
        ecdsa_public_key = server_data.pubkey

        verified_sig = verify_signature(ecdsa_public_key,ecdsa_message_generation_encoded,ecdsa_signature)
        if verified_sig == False:
            return jsonify({
                    'status': '200',
                    'message': 'Bad Request'
                    })
        else:
            if server_data == [] or server_data is None:
                return jsonify({
                        'status': '200',
                        'message': 'Bad Request'
                        })
            else:
                encrypted_key = server_data.key
                decrypted_key = decrypt_key(encrypted_key)
                ciphertext = ciphertext.encode()
                iv = iv.encode()
                iv = base64.b64decode(iv)
                ciphertext = base64.b64decode(ciphertext)
                print (" decrypt iv :", iv)
                print (" decrypt ciphertext :", ciphertext)
                print (" decrypt key :", decrypted_key)
                pt = decrypt_msg(decrypted_key,iv,ciphertext)
                print('Plain Text :', pt)
                pt_content = json.loads(pt)
                reg_name = pt_content.get('server_reg_name')

                if reg_name == server_data.server_reg_name:
                    server_data.server_reg_confirm = True
                    db.session.commit()
                    print('Finally reached')
                    return jsonify({
                        'status': '200',
                        'message': 'ALL_OK'
                        })
                else:
                    return jsonify({
                        'status': '200',
                        'message': 'Bad Request'
                        })


@api.route('/v1/iot_server/device_registration', methods=['POST'])
@limiter.exempt
def iot_device_registration():
    remote_ip_addr = request.remote_addr
    # server_data = Iotserver.query.filter_by(remote_ip=remote_ip_addr).first()
    # if server_data == [] or server_data is None:
    #     return jsonify({
    #         'status': '200',
    #         'message': 'Bad Request'
    #                     })
    iotserver_data = Iotserver.query.filter_by(remote_ip = remote_ip_addr).first()
    if iotserver_data is None:
        return jsonify({
            'status': '200',
            'data': 'Invalid Message Format'
                    })
    server_id = iotserver_data.id
    content = request.get_json()
    id = content.get('id')
    if id == None:
        return jsonify({
            'status': '200',
            'data': 'Invalid Message Format'
                    })

    else:

        device_data = Iotdevice.query.filter_by(id=id, server_id = server_id).first()
        device_name = device_data.device_reg_name
        if device_data == [] or device_data == None:
            return jsonify({
                'message':'ID does not exist'   
            })

        else:
            return jsonify({
                'message':'ID exists',
                'device_name':device_name
            })



@api.route('/v1/iot_server/device_registration_confirm', methods=['POST'])
@limiter.exempt
def iot_device_registration_confirm():
    remote_ip_addr = request.remote_addr
    iotserver_data = Iotserver.query.filter_by(remote_ip = remote_ip_addr).first()
    if iotserver_data is None:
        return jsonify({
            'status': '200',
            'data': 'Invalid Message Format'
                    })
    server_id = iotserver_data.id
    content = request.get_json()
    id = content.get('id')
    if id == None:
        return jsonify({
            'status':'200',
            'data':'Invalid Message Format'
        })

    else:
        device_data = Iotdevice.query.filter_by(id=id, server_id=server_id).first()
        if device_data == [] or device_data == None:
            return jsonify({
                'message':'ID does not exist'   
            })

        else:
            device_data.device_reg_confirm = True
            device_data.is_active = True
            db.session.commit()
            return jsonify({
                'message':'Updated'
            })


@api.route('/v1/iot_server/generate_bill', methods=['POST'])
@limiter.exempt
def server_bill_data():
    print('Reached here finally')
    remote_ip_addr = request.remote_addr
    content = request.get_json()
    ciphertext = content.get('ciphertext')
    iv = content.get('iv')
    ecdsa_signature_bill_data = content.get('signature')
    if ciphertext == None and iv == None and ecdsa_signature_bill_data == None:
        return jsonify({
                    'status': '200',
                    'message': 'Invalid Message Format'
                    })
    server_data = Iotserver.query.filter_by(remote_ip=remote_ip_addr, is_active = True).first()
    if server_data is None:
        return jsonify({
                    'status': '200',
                    'message': 'Data Does Not Exist'
                    })
    ecdsa_message_raw_encoded = ciphertext.encode()
    ecdsa_message_generation = hashlib.sha256(ecdsa_message_raw_encoded)
    ecdsa_message_generation_encoded = ecdsa_message_generation.hexdigest()
    ecdsa_signature = b64decode(ecdsa_signature_bill_data)
    ecdsa_public_key = server_data.pubkey
    verified_sig = verify_signature(ecdsa_public_key,ecdsa_message_generation_encoded,ecdsa_signature)
    if verified_sig == False:
        return jsonify({
                    'status': '200',
                    'message': 'Data not verified'
                    })
    else:
        encrypted_key = server_data.key
        print('i.key',server_data.key)
        decrypted_key = decrypt_key(encrypted_key)
        ciphertext = ciphertext.encode()
        iv = iv.encode()
        iv = base64.b64decode(iv)
        ciphertext = base64.b64decode(ciphertext)
        pt = decrypt_msg(decrypted_key,iv,ciphertext)
        pt_content = json.loads(pt)
        print('pt_contnt',pt_content)
        bill_units = pt_content.get('device_unit_data')
        print('Plain Text :', bill_units)
        gen_bill(bill_units, server_data.id) # add delay
        



    return 'done'

    





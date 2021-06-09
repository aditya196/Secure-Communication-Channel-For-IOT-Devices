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
                                Miscellaneous)
from iot_security import db
import base64
from base64 import b64encode
from base64 import b64decode
from requests.exceptions import HTTPError


def main_billing(units,prop_type):
    
    # -- Cost of Units as per Slab
    sl_cost = calc_slab(units,prop_type)
    sl_amt = 0.0
    if isinstance (sl_cost, dict):
        for k,v in sl_cost.items():
            if k == 'total':
                sl_amt = float(v)
    
    # -- Tax Calcutated
    tax_cost = calc_tax(sl_amt)
    tot_tax = 0.0
    if isinstance (tax_cost, dict):
        for k,v in tax_cost.items():
            for k1, v1 in v.items():
                if k1 == 'cost':
                    tot_tax = tot_tax + float(v1)
    
    # -- Misc Amount Calculation 
    misc_cost = calc_misc()
    m_cost = 0.0
    if isinstance (misc_cost, dict):
        for k,v in misc_cost.items():
            for k1, v1 in v.items():
                if k1 == 'amount':
                    m_cost = m_cost + float(v1)
    
    
    print ('sl cost :' , sl_amt)
    print ('tot tax :', tot_tax)
    print ('m cost :', m_cost)
    total_bill = sl_amt + tot_tax + m_cost
    data = {
        'slab_cost' : [sl_cost],
        'total' : total_bill
    }

    if m_cost != 0.0:
        data['misc_cost'] = [misc_cost]
    if tot_tax != 0.0:
        data['tax_cost'] = [tax_cost]

    return data

def late_billing(units,prop_type):
    
    # -- Cost of Units as per Slab
    sl_cost = calc_slab_penalty(units,prop_type)
    sl_amt = 0.0
    if isinstance (sl_cost, dict):
        for k,v in sl_cost.items():
            if k == 'total':
                sl_amt = float(v)
    
    # -- Tax Calcutated
    tax_cost = calc_tax(sl_amt)
    tot_tax = 0.0
    if isinstance (tax_cost, dict):
        for k,v in tax_cost.items():
            for k1, v1 in v.items():
                if k1 == 'cost':
                    tot_tax = tot_tax + float(v1)
    
    # -- Misc Amount Calculation 
    misc_cost = calc_misc()
    m_cost = 0.0
    if isinstance (misc_cost, dict):
        for k,v in misc_cost.items():
            for k1, v1 in v.items():
                if k1 == 'amount':
                    m_cost = m_cost + float(v1)
    
    
    print ('sl cost :' , sl_amt)
    print ('tot tax :', tot_tax)
    print ('m cost :', m_cost)
    total_bill = sl_amt + tot_tax + m_cost
    data = {
        'slab_cost' : [sl_cost],
        'tax_cost' : [tax_cost],
        'misc_cost' : [misc_cost],
        'total' : total_bill
    }
    return data

def calc_slab_penalty(units, prop_type):
    units = int(units)
    slab_data = Slablog.query.all()
    sl_data = {'units' : units}
    for i in slab_data:
        # -- Check which slab does the units lie in and calculate the cost + penalty accordingly
        lower_limit = int(i.lower_slab)
        if i.upper_slab != 'MAX':
            upper_limit = int(i.upper_slab)
            if units in range(lower_limit,upper_limit+1):
                if prop_type:
                    sl_cost = units * float(i.housing)
                    sl_cost = sl_cost + float(i.penalty)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    sl_data['penalty'] = float(i.penalty)
                    break
                else:
                    sl_cost = units * float(i.commercial)
                    sl_cost = sl_cost + float(i.penalty)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    slab_data['penalty'] = float(i.penalty)
                    break
                continue
        else:
            if units >= lower_limit:
                if prop_type:
                    sl_cost = units * float(i.housing)
                    sl_cost = sl_cost + float(i.penalty)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    slab_data['penalty'] = float(i.penalty)
                    break
                else:
                    sl_cost = units * float(i.commercial)
                    sl_cost = sl_cost + float(i.penalty)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    slab_data['penalty'] = float(i.penalty)
                    break
            continue
    return sl_data


def calc_slab(units, prop_type):
    units = int(units)
    slab_data = Slablog.query.all()
    sl_data = {'units' : units}
    for i in slab_data:
        # -- Check which slab does the units lie in and calculate the cost accordingly
        lower_limit = int(i.lower_slab)
        if i.upper_slab != 'MAX':
            upper_limit = int(i.upper_slab)
            if units in range(lower_limit,upper_limit+1):
                if prop_type:
                    sl_cost = units * float(i.housing)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    break
                else:
                    sl_cost = units * float(i.commercial)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    break
                continue
        else:
            if units >= lower_limit:
                if prop_type:
                    sl_cost = units * float(i.housing)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    break
                else:
                    sl_cost = units * float(i.commercial)
                    sl_data['slab_cost'] = float(i.housing)
                    sl_data['total'] = sl_cost
                    break
            continue
    return sl_data


def calc_misc():
    
    misc_data = Miscellaneous.query.all()
    if misc_data == [] or misc_data is None:
        return 0.0
    
    else:
        misc_dict_data = {}
        misc_cost = 0.0
        count = 0
        for i in misc_data:
            count += 1
            misc_dict_data[count] = {} 
            misc_dict_data[count]['name'] = i.name
            misc_dict_data[count]['amount'] = float(i.amount)
            misc_cost = misc_cost + float(i.amount)
        return misc_dict_data



def calc_tax(amount):
    amount = float(amount)
    tax_data = Tax.query.all()
    if tax_data == [] or tax_data is None:
        return 0.0

    else:
        tax_dict_data = {}
        total_tax = 0.0
        count = 0
        for i in tax_data:
            count += 1
            tax_dict_data[count] = {}
            tax_cost = 0
            tax_cost = amount * float(i.tax_rate)
            tax_cost = tax_cost / 100
            tax_dict_data[count]['name'] = i.tax_name
            tax_dict_data[count]['rate'] = float(i.tax_rate)
            tax_dict_data[count]['cost'] = tax_cost
            total_tax = total_tax + tax_cost
        
        return tax_dict_data


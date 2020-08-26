import base64
import json
import logging
import random
import re
from datetime import datetime

from flask import Flask, abort, render_template, request
from flask.json import jsonify

from flask_cors import CORS
from google.cloud import ndb
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from flask_jwt_extended import jwt_optional,get_jwt_identity
from werkzeug.security import safe_str_cmp
from flask_jwt import JWT

from flask_jwt import jwt_required, current_identity
from werkzeug.security import safe_str_cmp

client = ndb.Client()

class MEMBER(ndb.Model):
    username = ndb.StringProperty()
    password = ndb.StringProperty()
    email = ndb.StringProperty()
    kind = ndb.StringProperty()
    isadmin = ndb.BooleanProperty()
    created_at = ndb.StringProperty()
    updated_at = ndb.StringProperty()


def ndb_wsgi_middleware(wsgi_app):
    def middleware(environ, start_response):
        with client.context():
            return wsgi_app(environ, start_response)
    return middleware



app = Flask(__name__)
CORS(app)
app.wsgi_app = ndb_wsgi_middleware(app.wsgi_app)
app.config['JWT_SECRET_KEY'] = 'Mowgli Mowgli ! Super Mowgli!' 
jwt = JWTManager(app)

class MEMBER(ndb.Model):
    username = ndb.StringProperty()
    password = ndb.StringProperty()
    email = ndb.StringProperty()
    kind = ndb.StringProperty()
    isadmin = ndb.BooleanProperty()
    created_at = ndb.StringProperty()
    updated_at = ndb.StringProperty()

@app.route('/member-list')
def list_member():
    member_data = MEMBER.query()
    data_list = []
    for datas in member_data:
        memdata = {
             "id": str(datas.key.id()),
             "username": datas.username,
             "password": datas.password,
             "email": datas.email,
             "kind": datas.kind,
             "isadmin": datas.isadmin
        }
        data_list.append(memdata)
    return jsonify(data_list)

@app.route('/login', methods=['POST'])
def login():
    try:
        data = json.loads(request.data)
        user = MEMBER()
        query = user.query(MEMBER.email == data['email'], MEMBER.password == data['password'])
        admin = query.fetch()
        output = list(query.fetch())
        print(output)
        access_token = create_access_token(data['email'])
        if len(output) == 0 :
            return jsonify({"message": "Your password is incorrect", "status": False}),200
        else:
            return jsonify({"access_token":access_token, "status": True}), 200
    except Exception as e:
        return jsonify('Member Detail Error Occurs'+str(e)), 400


@app.route('/member-add', methods=["POST"])
def member_save():
    try:
        datas = json.loads(request.data)
        member_name = datas['username']
        member_password = datas['password']
        member_email = datas['email']
        member_kind = datas['kind']
        member_isadmin = datas['isadmin']
        member_data = MEMBER(
            username=member_name,
            password=member_password,
            email=member_email,
            kind=member_kind,
            isadmin=member_isadmin,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat())

        member_data.put()
        return jsonify("MemberData Add Success")
    except Exception as e:
       return jsonify("MemberData Add Fail"+str(e))


@app.route('/member-detail/<id>', methods=['GET'])
def member_detail(id):
    try:
        member_data = MEMBER.get_by_id(int(id))
        if member_data:
            data = {
                'id':member_data.key.id(),
                'username': member_data.username,
                'password': member_data.password,
                'kind': member_data.kind,
                'email': member_data.email,
                'isadmin': member_data.isadmin,
                'created_at': member_data.created_at,
                'updated_at': member_data.updated_at
            }
            return data
        else:
            return jsonify("Member Id is undefined"), 400
    except Exception as e:
        return jsonify('Member Detail Error Occurs'+str(e)), 400



@app.route('/member-update/<id>', methods=['PUT'])
def member_update(id):
    try:
        data = json.loads(request.data)
        MemberData = MEMBER()
        member_data = MEMBER.get_by_id(int(id))
        if member_data:
            member_data.username = data['username']
            member_data.password = data['password']
            member_data.email = data['email']
            member_data.kind = data['kind']
            member_data.isadmin = data['isadmin']
            member_data.updated_at = datetime.now().isoformat()
            MemberData = MEMBER(
                username=member_data.username,
                password=member_data.password,
                email=member_data.email,
                kind=member_data.kind,
                isadmin=member_data.isadmin,
                created_at=member_data.created_at,
                updated_at=datetime.now().isoformat(),
                key=member_data.key)
            MemberData.put()
            return jsonify("success update")
    except Exception as e:
        return jsonify('Update Error Occurs'+str(e)), 400



@app.route('/member-delete/<id>', methods=['DELETE'])  
def member_delete(id):
    try:
        deldata = MEMBER.get_by_id(int(id))
        if deldata:
            deldata.key.delete()
            return jsonify('Delete Successful')
        else:
            return jsonify('Invalid Id'), 400
    except Exception as e:
        return jsonify('Delete Error Occurs'), 400



class TELEPHONE(ndb.Model):
    name = ndb.StringProperty()
    kind = ndb.StringProperty()
    title = ndb.StringProperty()
    body = ndb.StringProperty()
    # attachment_url = ndb.StringProperty()
    # attachment_name = ndb.StringProperty()
    enable_resend_tel = ndb.BooleanProperty()
    created_at = ndb.StringProperty()
    updated_at = ndb.StringProperty()

@app.route('/')
def index():
    return 'Welcome From API TELEPHONE TESTING'


@app.route('/list')
def list_phone():
    telephones_data = TELEPHONE.query()
    data_list = []
    for data in telephones_data:
        teldata = {
             "id": str(data.key.id()),
             "body": data.body,
             "enable_resend_tel": data.enable_resend_tel,
             "kind": data.kind,
             "name": data.name,
             "title": data.title,
        }
        data_list.append(teldata)
    return jsonify(data_list)




@app.route('/add', methods=["POST"])
def save():
    try:
        data = json.loads(request.data)
        tel_body = data['body']
        tel_enable_resend_tel = data['enable_resend_tel']
        tel_kind = data['kind']
        tel_name = data['name']
        tel_title = data['title']
        # attachment_url = data['attachment_url']
        # attachment_name = data['attachment_name']
        telephones_data = TELEPHONE(
            body=tel_body,
            enable_resend_tel=tel_enable_resend_tel, 
            kind=tel_kind,
            name=tel_name,
            title=tel_title,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat())

        telephones_data.put()
        return jsonify("Telephonedata Add Success")
    except Exception as e:
       return jsonify("Telephonedata Add Fail")



@app.route('/update/<id>', methods=['PUT'])
def update(id):
    try:
        data = json.loads(request.data)
        Telephonedata = TELEPHONE()
        telephones_data = TELEPHONE.get_by_id(int(id))
        if telephones_data:
            telephones_data.title = data['title']
            telephones_data.name = data['name']
            telephones_data.body = data['body']
            telephones_data.enable_resend_tel = data['enable_resend_tel']
            telephones_data.kind = data['kind']
            telephones_data.updated_at = datetime.now().isoformat()
            Telephonedata = TELEPHONE(
                title=telephones_data.title,
                name=telephones_data.name,
                body=telephones_data.body,
                enable_resend_tel=telephones_data.enable_resend_tel,
                kind=telephones_data.kind,
                created_at=telephones_data.created_at,
                updated_at=datetime.now().isoformat(),
                key=telephones_data.key)
            Telephonedata.put()
            return jsonify("success update")
    except Exception as e:
        return jsonify('Update Error Occurs'+str(e)), 400

@app.route('/detail/<id>', methods=['GET'])
def detail(id):
    try:
        telephones_data = TELEPHONE.get_by_id(int(id))
        if telephones_data:
            data = {
                'id':telephones_data.key.id(),
                'name': telephones_data.name,
                'title': telephones_data.title,
                'body': telephones_data.name,
                'kind': telephones_data.kind,
                'enable_resend_tel': telephones_data.enable_resend_tel,
                'created_at': telephones_data.created_at,
                'updated_at': telephones_data.updated_at
            }
            return data
        else:
            return jsonify("Telephone Id is undefined"), 400
    except Exception as e:
        return jsonify('Telephone Detail Error Occurs'+str(e)), 400


@app.route('/delete/<id>', methods=['DELETE'])  
def delete(id):
    try:
        deldata = TELEPHONE.get_by_id(int(id))
        if deldata:
            deldata.key.delete()
            return jsonify('Delete Successful')
        else:
            return jsonify('Invalid Id'), 400
    except Exception as e:
        return jsonify('Delete Error Occurs'), 400



if __name__ == '__main__':
    app.run(debug=True)

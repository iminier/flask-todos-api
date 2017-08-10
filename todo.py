from credentials import *
from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from functools impoer wraps
import uuid
import jwt
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = secretoKey
app.config['MONGO_URI'] = dbURI

db = PyMongo(app)

def token_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		token = None
	
		if 'x-access-token' in request.headers:
			token = request.headers['x-access-token']

		if not token:
			return jsonify({'message' : 'Token is missing!'}), 401

		try
			data = jwt.decode(token, app.config['SECRET_KEY']
			current_user = User.query.filer_by(public_id = data['public_id']).first()
		except:
			return jsonify({'message' : 'Token is invalid'}), 401
	
		return f(current_user, *args, **kwargs)
	
	return decorated

@app.route('/user', methods = ['GET'])
@token_required
def get_all_users(current_user):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	users = db.mongo.users
	
	output = []

	for users in users:
		user_data = {}
		user_data['unique_id'] = user._id
		user_data['name'] = user.name
		user_data['password'] = user.password
		user_data['admin'] = user.admin
		
		output.append(user_data)
	
	jsonify({'users' : output })

@app.route('/user/<unique_id>', methods = ['GET'])
@token_required
def get_one_user(current_user, unique_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform function'})
	
# need to query the db correctly
	user = 
User.query.filter_by(unique_id = unique_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	user_data = {}
	user_data['unique_id'] = user._id
	user_data['name'] = user.name
	user_data['password'] = user.password
	user_data['admin'] = user.admin

	return jsonify({'user' : user_data})

from keyData import *
from dbData import *
from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
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

		try:
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
	#
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
	# 
	user = db.query.filter_by(unique_id = unique_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})

	user_data = {}
	user_data['unique_id'] = user._id
	user_data['name'] = user.name
	user_data['password'] = user.password
	user_data['admin'] = user.admin

	return jsonify({'user' : user_data})


@app.route('/user', methods = ['POST'])
@token_required
def create_user(current_user):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})
	
	data = request.get_json()

	hashed_password = generate_password_hash(data['password'], method = 'sha256')

	new_user = {'name' = data['name'], password = hashed_password, admin = False)
	#
	db.add(new_user)
	db.save()

	return jsonify({'message' : 'New user created!'})


@app.route('/user/<public_id>', methods = ['PUT'])
@token_required
def promote_user(current_user, unique_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	user = db.query.filter_by(public_id=public_id).first()

	if not user:
		return jsonify({'message' : 'No user found!'})
	#
	user.admin = True
	db.save(user)

	return jsonify({'message' : 'User has been promoted'})


@app.route('/user/<unique_id>', methods = ['DELETE'])
@token_required
def delete_user(current_user, unique_id):
	if not current_user.admin:
		return jsonify({'message' : 'Cannot perform that function!'})

	#
	user = db.query.filter_by(unique_id = unique_id).first()

	if not user:
		return jsonify({'message' : 'No user found'})

	db.delete(user)

	return jsonify({'message' : 'The user has been deleted!'})


@app.route('/login')
def login():
	auth = request.authorization

	if not auth or not auth.username or not auth.password:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm = "Login required!"'})

	#
	user = db.query.filter_by(name = auth.username).first()

	if not user:
		return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm = "Login required!"'})

	if check_password_hash(user.password, auth.password):
		token = jwt.encode({'unique_id' : user._id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes = 30)}, app.config['SECRET_KEY'])
		return jsonify({'token' : token.decode('UTF-8')})

	return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm = "Login required!"'})


@app.route('/todo', methods = ['GET'])
@token_required
def get_all_todos(current_user):
	#
	todos = todoDB.query.filter_by(user_id = current_user.id).all()
	
	output = []

	for todo in todos:
		todo_data = {}
		todo_data['id'] = todo.id
		todo_data['text'] = todo.text
		todo_data['complete'] = todo.complete
		output.append(todo_data)

	return jsonify({'todos' : output})


@app.route('/todo/<todo_id>', methods = ['GET'])
@token_required
def get_one_todo(current_user, todo_id):
	#
	todo = todoDB.query.filter_by(id = todo_id, user_id = current_user.id).first()

	if not todo:
		return jsonify({'message' : 'No todo founds!'})

	todo_data = {}
	todo_data['id'] = todo.id
	todo_data['text'] = todo.text
	todo_data['complete'] = todo.complete

	return jsonify(todo_data)


@app.route('/todo', methods = ['POST'])
@token_required
def create_todo(current_user):
	data = request.get_json()

	new_todo = {}
	new_todo['text'] = data['text']
	new_todo['user_id'] = current_user.id
	new_todo['complete'] = False

	#
	db.add(new_todo)

	return jsonify({'message' : 'Todo created!'})


@app.route('/todo/<todo_id>', methods = ['PUT'])
@token_required
def complete_todo(current_user, todo_id):
	#
	todo = db.query.filter_by(id = todo_id, user_id = current_user.id).first()

	if not todo:
		return jsonify({'message' : 'No todo found!'})

	todo.complete = True
	#
	db.save()

	return jsonify({'message' : 'Todo item has been marked completed!'})


@app.route('/todo/<todo_id>', methods = ['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
	#
	todo = db.query.filter_by(id = todo_id, user_id = current_user.id).first()

	if not todo:
		return jsonify({'message' : 'No todo found!'})

	db.delete(todo)
	
	return jsonify({'message' : 'Todo item deleted!'})


if __name__ == '__main__':
	app.debug = True
	app.run(host = '0.0.0.0')

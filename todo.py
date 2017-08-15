from keyData import *
from dbData import *
from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from bson.objectid import ObjectId
import uuid
import jwt
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = secretoKey
app.config['MONGO_DBNAME'] = dbname
app.config['MONGO_URI'] = dbURI

mgdb = PyMongo(app)


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
    
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = mgdb.db.users.find_one({'_id' : ObjectId(str(data['unique_id']))})

        except:
            return jsonify({'message' : 'Token is invalid 100'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated


##
# ROUTES
##

@app.route('/user', methods = ['POST'])
def create_user():
    
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method = 'sha256')

    new_user = {'name' : data['name'], 'password' : hashed_password, 'admin' : False}
    ####
    mgdb.db.users.insert(new_user)

    return jsonify({'message' : 'New user created!'})


@app.route('/login')
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm = "Login required!"'})

    user = mgdb.db.users.find_one({'name' : auth.username})

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm = "Login required!"'})
    
    if check_password_hash(user['password'], auth.password):
        token = jwt.encode({'unique_id' : str(user['_id']), 
                            'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes = 30)}, 
                            app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})
    
    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm = "Login required!"'})


@app.route('/user', methods = ['GET'])
@token_required
def get_all_users(current_user):
    if not current_user['admin']:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = mgdb.db.users.find()
    
    output = []

    for user in users:
        user_data = {}
        user_data['unique_id'] = str(user['_id'])
        user_data['name'] = str(user['name'])
        user_data['admin'] = str(user['admin'])
        
        output.append(user_data)
    
    return jsonify({'users' : output })


@app.route('/user/<unique_id>', methods = ['GET'])
@token_required
def get_one_user(current_user, unique_id):
    if not current_user['admin']:
        return jsonify({'message' : 'Cannot perform function'}) 
    #### 
    user = mgdb.db.users.find_one({'_id' : ObjectId(str(unique_id))})

    if not user:
        return jsonify({'message' : 'No user found!'})

    if 'admin' not in user:
        user['admin'] = False
        mgdb.db.users.update_one({
            '_id' : user['_id']
            },{
                '$set' : {
                    'admin' : user['admin'] 
                }
            }, upsert = False)

    user_data = {}
    user_data['unique_id'] = str(user['_id'])
    user_data['name'] = user['name']
    user_data['admin'] = str(user['admin'])

    return jsonify({'user' : user_data})


@app.route('/user/makeAdmin/<unique_id>', methods = ['PUT'])
@token_required
def promote_user(current_user, unique_id):
    if not current_user['admin']:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = mgdb.db.users.find_one({'_id' : ObjectId(str(unique_id))})

    if not user:
        return jsonify({'message' : 'No user found!'})

    if 'admin' not in user:
        user['admin'] = False
        mgdb.db.users.update_one({
            '_id' : user['_id']
            },{
                '$set' : {
                    'admin' : user['admin'] 
                }
            }, upsert = False)
    
    user['admin'] = True
    
    mgdb.db.users.update_one({
        '_id' : user['_id']
        },{
            '$set' : {
                'admin' : user['admin']
            }
    }, upsert=False) 

    return jsonify({'message' : 'User has been promoted'})


@app.route('/user/delete/<unique_id>', methods = ['DELETE'])
@token_required
def delete_user(current_user, unique_id):
    if not current_user['admin']:
        return jsonify({'message' : 'Cannot perform that function!'})

    ####
    user = mgdb.db.users.find_one({'_id' : ObjectId(str(unique_id))})

    if not user:
        return jsonify({'message' : 'No user found'})

    ####
    mgdb.db.users.remove({'_id' : ObjectId(str(unique_id))})

    return jsonify({'message' : 'The user has been deleted!'})


####
## Todo Methods
####


@app.route('/todo', methods = ['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()

    new_todo = {}
    new_todo['todo_id'] = str(uuid.uuid4())
    new_todo['text'] = data['text']
    new_todo['user_id'] = current_user['_id']
    new_todo['complete'] = False
    
    mgdb.db.todos.insert(new_todo)

    

    return jsonify({'message' : 'Todo created!'})


@app.route('/todo', methods = ['GET'])
@token_required
def get_all_todos(current_user):
    todos = mgdb.db.todos.find({'user_id' : ObjectId(str(current_user['_id']))})  

    output = []

    for todo in todos:
        todo_data = {}
        todo_data['todo_id'] = todo['todo_id']
        todo_data['text'] = todo['text']
        todo_data['complete'] = todo['complete']
        output.append(todo_data)

    return jsonify({'todos' : output})


@app.route('/todo/<todo_id>', methods = ['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    ####
    todo = mgdb.db.todos.find_one({'todo_id' : str(todo_id)})

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    todo_data = {}
    todo_data['todo_id'] = todo['todo_id']
    todo_data['text'] = todo['text']
    todo_data['complete'] = todo['complete']

    return jsonify(todo_data)


@app.route('/todo/markComplete/<todo_id>', methods = ['PUT'])
@token_required
def complete_todo(current_user, todo_id):
    #
    todo = mgdb.db.todos.find_one({'todo_id' : str(todo_id)})

    if not todo:
        return jsonify({'message' : 'No todo found!'})

    todo['complete'] = True
    
    mgdb.db.todos.update_one({
        'todo_id' : str(todo_id)
        },{
            '$set' : {'complete' : todo['complete']}
        }, upsert = False) 

    return jsonify({'message' : 'Todo item has been marked completed!'})


@app.route('/todo/delete/<todo_id>', methods = ['DELETE'])
@token_required
def delete_todo(current_user, todo_id):

    todo = mgdb.db.todos.find_one({'todo_id' : str(todo_id)})

    if not todo:
        return jsonify({'message' : 'No todo found'})

    mgdb.db.todos.remove({'todo_id' : str(todo_id)})
    
    return jsonify({'message' : 'Todo item deleted!'})


if __name__ == '__main__':
    app.debug = True
    app.run(host = '0.0.0.0')


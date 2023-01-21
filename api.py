import uuid
from functools import wraps, partial
import jwt
import datetime
from settings import PATH_TO_DB, STATUS_CODE_201_CREATE, STATUS_CODE_200_SUCCESS, STATUS_CODE_404_NOTFOUND, \
    STATUS_CODE_204_NOTCONTENT, STATUS_CODE_500_INTERNALERROR, STATUS_CODE_202_ACCEPT, STATUS_CODE_401_UNATHORIZATED, \
    STATUS_CODE_405_NOTALLOWED
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy  # pip install -U Flask-SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from os import getenv
from dotenv import load_dotenv

load_dotenv('secrete.env')
app = Flask(__name__)

# some config:

# token settings
app.config['SECRET_KEY'] = getenv("SECRET_KEY")
# database path settings
app.config['SQLALCHEMY_DATABASE_URI'] = PATH_TO_DB

# database
db = SQLAlchemy(app)


# tables in database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    description = db.Column(db.String(100))
    complete = db.Column(db.Boolean)


# LOGIN view (1h token expiration)
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('FAILED: Could not verify',
                             STATUS_CODE_401_UNATHORIZATED,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return make_response('FAILED: No user found',
                             STATUS_CODE_204_NOTCONTENT,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=3600),
                            }, app.config['SECRET_KEY'])
        return jsonify({'token': token})

    return make_response('FAILED: Could not verify',
                         STATUS_CODE_401_UNATHORIZATED,
                         {'WWW-Authenticate': 'Basic realm="Login required!"'})


def token_required(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        token = None
        if 'X-Access-Token' in request.headers:
            token = request.headers['X-Access-Token']

        elif not token:
            return jsonify({'message': 'Token is missing!'})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), STATUS_CODE_401_UNATHORIZATED
        return fn(current_user, *args, **kwargs)
    return decorated


# ERROR views
@app.errorhandler(404)
def not_found(e):
    return jsonify({'OPS': 'Route not found!'}), STATUS_CODE_404_NOTFOUND


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'ERROR': 'INTERNAL ERROR!'}), STATUS_CODE_500_INTERNALERROR


@app.errorhandler(405)
def not_allowed(e):
    return jsonify({'FAILED': 'METHOD NOT ALLOWED!'}), STATUS_CODE_405_NOTALLOWED


# LOGIN REQUIRED views (routes)
@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = User.query.all()
    output = list()

    if not users:
        jsonify({'Users': output}), STATUS_CODE_204_NOTCONTENT

    for user in users:
        data = dict()
        data['name'] = user.name
        data['public_id'] = user.public_id
        data['password'] = user.password
        data['admin'] = user.admin
        output.append(data)

    return jsonify({'Users': output}), STATUS_CODE_200_SUCCESS


@app.route('/users/<user_id>', methods=['GET'])
@token_required
def get_one_user(current_user, user_id):
    user = User.query.filter_by(public_id=user_id)

    if not user:
        return jsonify({"error": "User not found!"}), STATUS_CODE_204_NOTCONTENT

    output = list()
    for user in user:
        data = dict()
        data['name'] = user.name
        data['public_id'] = user.public_id
        data['password'] = user.password
        data['admin'] = user.admin
        output.append(data)
    return jsonify({'message': output}), STATUS_CODE_200_SUCCESS


@app.route('/users', methods=['POST'])
@token_required
def create_new_user(current_user):
    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['name'],
                    password=hashed_password,
                    admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({
        'message': "The user has been created!"}), STATUS_CODE_201_CREATE


@app.route('/users/<user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    user = User.query.filter_by(public_id=user_id).first()

    if not user:
        jsonify({'Users': {}}), STATUS_CODE_204_NOTCONTENT

    data = request.get_json()
    try:
        if data['name']:
            user.name = data['name']
    except KeyError as e:
        pass
    try:
        if data['password']:
            user.password = generate_password_hash(data['password'], method='sha256')
    except KeyError as e:
        pass
    try:
        if data['admin']:
            user.admin = data['admin']
    except KeyError as e:
        pass
    db.session.commit()
    return jsonify({'message': f'User: {user_id} was successfull updated!'}), STATUS_CODE_201_CREATE


@app.route('/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    user = User.query.filter_by(public_id=user_id).first()

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': f'User: {user_id} has been deleted!'}), STATUS_CODE_202_ACCEPT


@app.route('/todo', methods=['GET'])
@token_required
def get_all_todo(current_user):
    todo = Todo.query.all()
    todo_data = list()
    for do in todo:
        response = dict()
        response['todo_id'] = do.id
        response['description'] = do.description
        response['complete'] = do.complete
        todo_data.append(response)
    return jsonify({'all-to-do': todo_data}), STATUS_CODE_200_SUCCESS


@app.route('/todo/<todo_id>', methods=['GET'])
@token_required
def get_one_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=current_user.id).first()
    todo_data = list()

    response = dict()
    response['todo_id'] = todo.id
    response['description'] = todo.description
    response['complete'] = todo.complete
    todo_data.append(response)
    return jsonify({'all-to-do': todo_data}), STATUS_CODE_200_SUCCESS


@app.route('/todo', methods=['POST'])
@token_required
def create_todo(current_user):
    data = request.get_json()
    todo = Todo(user_id=int(current_user.id),
                description=data['description'],
                complete=data['complete'])
    db.session.add(todo)
    db.session.commit()
    return jsonify({'to-do': 'Task add successfully!'}), STATUS_CODE_201_CREATE


@app.route('/todo/<todo_id>', methods=['PUT'])
@token_required
def update_todo(current_user, todo_id):
    data = request.get_json()
    todo = Todo.query.filter_by(user_id=int(todo_id)).first()
    print(todo_id)
    if not todo:
        make_response('FAILED: Task not found',
                      STATUS_CODE_204_NOTCONTENT,
                      )

    if data.get('description'):
        todo.description = data.get('description')
    if data.get('complete'):
        todo.complete = data.get('complete')

    db.session.commit()

    return jsonify({'to-do': 'Task updated successfully!'}), STATUS_CODE_202_ACCEPT


@app.route('/todo/<todo_id>', methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(user_id=todo_id).first()

    db.session.delete(todo)
    db.session.commit()

    return jsonify({'to-do': 'Task has been deleted!'}), STATUS_CODE_202_ACCEPT


if __name__ == '__main__':
    app.run(debug=True, port=7777)

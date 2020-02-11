from server import db, app
import jwt
from functools import wraps
from flask import request, jsonify
from server.models import User
from werkzeug.security import generate_password_hash, check_password_hash

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['KEY'])
            _id = data['user_id']
            current_user = User.query.get(_id)
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['GET', 'POST'])
def register():
    name = request.json.get('name')
    username = request.json.get('username')
    password = request.json.get('password')

    hashed_password = generate_password_hash(password)

    user = User(
        name = name,
        username = username,
        password = hashed_password
    )

    db.session.add(user)
    db.session.commit()

    print(User.query.all())
    
    return jsonify({'message': 'successfully registered!'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not request.json.get('username') or not request.json.get('password'):
        return jsonify({'message': 'could not verify'}), 401

    user = User.query.filter_by(username = request.json.get('username')).first()

    if not user:
        return jsonify({'message': 'could not verify'}), 401

    if check_password_hash(user.password, request.json.get('password')):
        token = jwt.encode(
            {
                'user_id': user.id,
                'username': user.username
            },
            app.config['KEY']
        )
        return jsonify({'token': token.decode('UTF-8')})
    return jsonify({'message': 'could not verify'}), 401

@app.route('/test', methods=['GET', 'POST'])
def test():
    num = request.json.get('num')
    message = 'number you sent: ' + num
    return jsonify({'message': message})

@app.route('/login_required', methods=['POST', 'GET'])
@token_required
def login_required(current_user):
    return jsonify({'message': 'you can see this only if you are logged in'})

@app.route('/logout', methods=['GET', 'POST'])
@token_required
def logout(current_user):
    return jsonify({'message': 'logged out'})
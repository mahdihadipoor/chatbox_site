import os
import uuid
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, disconnect
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# --- App Configuration ---
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'a_super_secret_key_for_production'
app.config['JWT_SECRET_KEY'] = 'another_super_secret_jwt_key'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_BINDS'] = {
    'messages': 'sqlite:///messages.db'
}

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    display_name = db.Column(db.String(100))
    bio = db.Column(db.String(200))
    profile_image_url = db.Column(db.String(200), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserLoginInfo(db.Model):
    __tablename__ = 'user_login_info'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    login_timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    __bind_key__ = 'messages'
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(50), nullable=False)
    recipient_id = db.Column(db.String(50), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- HTTP Routes ---
@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')

@app.route('/panel', methods=['GET'])
def panel_page():
    return render_template('panel.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- API Endpoints ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username, 
        password_hash=hashed_password, 
        display_name=username
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password_hash, password):
        # Log user info
        new_log = UserLoginInfo(
            user_id=user.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(new_log)
        db.session.commit()

        access_token = create_access_token(identity=user.public_id)
        return jsonify(access_token=access_token)
    
    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/api/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=current_user_id).first_or_404()

    if request.method == 'GET':
        return jsonify({
            "username": user.username,
            "display_name": user.display_name,
            "bio": user.bio,
            "profile_image_url": url_for('uploaded_file', filename=user.profile_image_url, _external=True)
        })

    if request.method == 'PUT':
        data = request.get_json()
        user.display_name = data.get('display_name', user.display_name)
        user.bio = data.get('bio', user.bio)
        db.session.commit()
        return jsonify({"msg": "Profile updated successfully"})

@app.route('/api/profile/photo', methods=['POST'])
@jwt_required()
def profile_photo():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=current_user_id).first_or_404()
    
    if 'photo' not in request.files:
        return jsonify({"msg": "No file part"}), 400
    file = request.files['photo']
    if file.filename == '':
        return jsonify({"msg": "No selected file"}), 400
    
    if file:
        filename = secure_filename(f"{current_user_id}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        user.profile_image_url = filename
        db.session.commit()
        return jsonify({"msg": "Photo updated successfully", "url": url_for('uploaded_file', filename=filename, _external=True)})

@app.route('/api/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    users = User.query.filter(User.public_id != current_user_id).all()
    user_list = [{
        "public_id": u.public_id,
        "display_name": u.display_name,
        "profile_image_url": url_for('uploaded_file', filename=u.profile_image_url, _external=True)
    } for u in users]
    return jsonify(user_list)

@app.route('/api/messages/<recipient_id>', methods=['GET'])
@jwt_required()
def get_messages(recipient_id):
    sender_id = get_jwt_identity()
    
    messages = db.session.query(Message).filter(
        ((Message.sender_id == sender_id) & (Message.recipient_id == recipient_id)) |
        ((Message.sender_id == recipient_id) & (Message.recipient_id == sender_id))
    ).order_by(Message.timestamp).all()

    message_list = [{
        "sender_id": m.sender_id,
        "text": m.text,
        "timestamp": m.timestamp.isoformat()
    } for m in messages]
    
    return jsonify(message_list)

# --- Socket.IO Events ---
@socketio.on('connect')
def on_connect():
    token = request.args.get('token')
    if not token:
        disconnect()
    try:
        # Simple verification, in production use Flask-JWT-Extended's verification
        pass
    except:
        disconnect()

@socketio.on('private_message')
@jwt_required()
def on_private_message(data):
    sender_id = get_jwt_identity()
    recipient_id = data['recipient_id']
    text = data['text']
    
    room = min(sender_id, recipient_id) + max(sender_id, recipient_id)
    
    new_message = Message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        text=text
    )
    db.session.add(new_message)
    db.session.commit()
    
    emit('new_private_message', {
        'sender_id': sender_id,
        'recipient_id': recipient_id,
        'text': text,
        'timestamp': datetime.utcnow().isoformat()
    }, to=room)

@socketio.on('join_room')
@jwt_required()
def on_join_room(data):
    sender_id = get_jwt_identity()
    recipient_id = data['recipient_id']
    room = min(sender_id, recipient_id) + max(sender_id, recipient_id)
    join_room(room)


if __name__ == '__main__':
    if not os.path.exists('static/uploads'):
        os.makedirs('static/uploads')
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=443, debug=True, allow_unsafe_werkzeug=True)
import os
from flask import Blueprint, request, jsonify, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from sqlalchemy import or_, and_, desc, not_
from datetime import datetime
from ..models import db, User, Message, BlockList
from ..sockets.events import user_sids
from .. import oauth

api_bp = Blueprint('api_bp', __name__)

@api_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    phone = data.get('phone_number')
    password = data.get('password')
    if not phone or not password:
        return jsonify({"msg": "Phone number and password are required"}), 400
    if User.query.filter_by(phone_number=phone).first():
        return jsonify({"msg": "Phone number already registered"}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(phone_number=phone, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "Registration successful! Please log in."}), 201

@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone_number')
    password = data.get('password')
    user = User.query.filter_by(phone_number=phone).first()

    if user and user.password_hash and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=user.public_id)
        refresh_token = create_refresh_token(identity=user.public_id)
        
        user.last_seen = datetime.utcnow()
        db.session.commit()

        return jsonify(
            access_token=access_token,
            refresh_token=refresh_token,
            profile_complete=(user.username is not None)
        )
    return jsonify({"msg": "Invalid phone number or password"}), 401
    
@api_bp.route('/login/google')
def google_login():
    redirect_uri = url_for('api_bp.google_auth_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@api_bp.route('/auth/google/callback')
def google_auth_callback():
    token = oauth.google.authorize_access_token()
    user_info = token.get('userinfo')
    
    user = User.query.filter_by(email=user_info.email).first()
    if not user:
        user = User(
            email=user_info.email,
            username=user_info.email,
            display_name=user_info.name,
            profile_image_url=user_info.picture,
        )
        db.session.add(user)
        db.session.commit()
    
    access_token = create_access_token(identity=user.public_id)
    refresh_token = create_refresh_token(identity=user.public_id)
    
    return redirect(f"/panel#access_token={access_token}&refresh_token={refresh_token}")

@api_bp.route('/complete-profile', methods=['POST'])
@jwt_required()
def complete_profile():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=current_user_id).first_or_404()

    if user.username:
        return jsonify({"msg": "Profile already completed"}), 400

    data = request.get_json()
    username = data.get('username')
    display_name = data.get('display_name')

    if not username or not display_name:
        return jsonify({"msg": "Username and display name are required"}), 400
    
    if User.query.filter(User.username == username, User.public_id != current_user_id).first():
        return jsonify({"msg": "Username is already taken"}), 409

    user.username = username
    user.display_name = display_name
    db.session.commit()
    return jsonify({"msg": "Profile completed successfully"})
    
@api_bp.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(public_id=current_user_id).first_or_404()

    if request.method == 'GET':
        return jsonify({
            "username": user.username,
            "display_name": user.display_name,
            "bio": user.bio,
            "profile_image_url": url_for('main_bp.uploaded_file', filename=user.profile_image_url, _external=True)
        })

    if request.method == 'PUT':
        data = request.get_json()
        user.display_name = data.get('display_name', user.display_name)
        user.bio = data.get('bio', user.bio)
        db.session.commit()
        return jsonify({"msg": "Profile updated successfully"})

@api_bp.route('/profile/photo', methods=['POST'])
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
        upload_path = os.path.join('backend', 'static', 'uploads', filename)
        file.save(upload_path)
        user.profile_image_url = filename
        db.session.commit()
        return jsonify({"msg": "Photo updated successfully", "url": url_for('main_bp.uploaded_file', filename=filename, _external=True)})

@api_bp.route('/conversations', methods=['GET'])
@jwt_required()
def get_conversations():
    current_user_id = get_jwt_identity()
    
    blocked_by_others = db.session.query(BlockList.blocker_id).filter_by(blocked_id=current_user_id).all()
    blocked_by_others_ids = {b[0] for b in blocked_by_others}

    participants1 = db.session.query(Message.recipient_id).filter(Message.sender_id == current_user_id).distinct()
    participants2 = db.session.query(Message.sender_id).filter(Message.recipient_id == current_user_id).distinct()
    
    participant_ids = {p[0] for p in participants1}.union({p[0] for p in participants2})
    valid_participant_ids = [pid for pid in participant_ids if pid not in blocked_by_others_ids]

    conversations = []
    for pid in valid_participant_ids:
        user = User.query.filter_by(public_id=pid).first()
        if user:
            last_message = Message.query.filter(or_(and_(Message.sender_id == current_user_id, Message.recipient_id == pid), and_(Message.sender_id == pid, Message.recipient_id == current_user_id))).order_by(desc(Message.timestamp)).first()
            conversations.append({
                "with_user": {"public_id": user.public_id, "display_name": user.display_name, "profile_image_url": url_for('main_bp.uploaded_file', filename=user.profile_image_url, _external=True)},
                "last_message": { "text": last_message.text if last_message else "...", "timestamp": last_message.timestamp.isoformat() if last_message else ""}
            })
    conversations.sort(key=lambda x: x['last_message']['timestamp'], reverse=True)
    return jsonify(conversations)

@api_bp.route('/search/users', methods=['GET'])
@jwt_required()
def search_users():
    query = request.args.get('q', '').strip()
    current_user_id = get_jwt_identity()

    if not query:
        return jsonify([])

    users = User.query.filter(
        User.public_id != current_user_id,
        or_(
            User.username.ilike(f'%{query}%'),
            User.display_name.ilike(f'%{query}%')
        )
    ).limit(10).all()

    user_list = [{
        "public_id": u.public_id,
        "display_name": u.display_name,
        "profile_image_url": url_for('main_bp.uploaded_file', filename=u.profile_image_url, _external=True)
    } for u in users]
    
    return jsonify(user_list)
    
@api_bp.route('/users/<public_id>', methods=['GET'])
@jwt_required()
def get_user_details(public_id):
    user = User.query.filter_by(public_id=public_id).first_or_404()
    return jsonify({
        "public_id": user.public_id,
        "display_name": user.display_name,
        "profile_image_url": url_for('main_bp.uploaded_file', filename=user.profile_image_url, _external=True)
    })

@api_bp.route('/users/<public_id>/block', methods=['POST'])
@jwt_required()
def block_user(public_id):
    blocker_id = get_jwt_identity()
    if BlockList.query.filter_by(blocker_id=blocker_id, blocked_id=public_id).first():
        return jsonify({"msg": "User already blocked"}), 400
    
    new_block = BlockList(blocker_id=blocker_id, blocked_id=public_id)
    db.session.add(new_block)
    db.session.commit()
    return jsonify({"msg": "User blocked successfully"})

@api_bp.route('/users/<public_id>/unblock', methods=['POST'])
@jwt_required()
def unblock_user(public_id):
    blocker_id = get_jwt_identity()
    block = BlockList.query.filter_by(blocker_id=blocker_id, blocked_id=public_id).first()
    if block:
        db.session.delete(block)
        db.session.commit()
    return jsonify({"msg": "User unblocked successfully"})

@api_bp.route('/messages/<recipient_id>', methods=['GET'])
@jwt_required()
def get_messages(recipient_id):
    sender_id = get_jwt_identity()
    messages = db.session.query(Message).filter(or_(and_(Message.sender_id == sender_id, Message.recipient_id == recipient_id), and_(Message.sender_id == recipient_id, Message.recipient_id == sender_id))).order_by(Message.timestamp).all()
    message_list = [{"id": m.id, "sender_id": m.sender_id, "text": m.text, "timestamp": m.timestamp.isoformat(), "is_read": m.is_read} for m in messages]
    return jsonify(message_list)
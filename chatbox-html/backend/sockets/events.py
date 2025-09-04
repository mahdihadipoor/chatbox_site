from flask_socketio import emit, disconnect
from flask import request
from flask_jwt_extended import decode_token
from datetime import datetime
from .. import socketio
from ..models import db, User, Message, BlockList

user_sids = {}

def get_user_id_from_token(token):
    try: return decode_token(token, allow_expired=True)['sub']
    except: return None

@socketio.on('connect')
def on_connect():
    token = request.args.get('token')
    user_id = get_user_id_from_token(token)
    if not user_id: return disconnect()
    user = User.query.filter_by(public_id=user_id).first()
    if user:
        user_sids[user_id] = request.sid
        user.last_seen = None
        db.session.commit()

@socketio.on('disconnect')
def on_disconnect():
    for user_id, sid in list(user_sids.items()):
        if sid == request.sid:
            del user_sids[user_id]
            user = User.query.filter_by(public_id=user_id).first()
            if user:
                user.last_seen = datetime.utcnow()
                db.session.commit()
            break

@socketio.on('private_message')
def on_private_message(data):
    sender_id = get_user_id_from_token(data.get('token'))
    if not sender_id: return
    recipient_id = data['recipient_id']
    if BlockList.query.filter_by(blocker_id=recipient_id, blocked_id=sender_id).first():
        return
    
    new_message = Message(sender_id=sender_id, recipient_id=recipient_id, text=data['text'])
    db.session.add(new_message)
    db.session.commit()

    payload = {'id': new_message.id, 'sender_id': sender_id, 'recipient_id': recipient_id, 'text': data['text'], 'timestamp': new_message.timestamp.isoformat(), 'is_read': False}
    
    if user_sids.get(recipient_id): emit('new_private_message', payload, to=user_sids.get(recipient_id))
    emit('new_private_message', payload, to=request.sid)

@socketio.on('mark_as_read')
def mark_as_read(data):
    user_id = get_user_id_from_token(data.get('token'))
    if not user_id: return
    partner_id = data.get('partner_id')
    if not partner_id: return

    Message.query.filter_by(sender_id=partner_id, recipient_id=user_id, is_read=False).update({'is_read': True})
    db.session.commit()

    if user_sids.get(partner_id):
        emit('messages_were_read', {'by_user': user_id}, to=user_sids.get(partner_id))
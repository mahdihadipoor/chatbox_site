from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, default=lambda: str(uuid.uuid4()))
    phone_number = db.Column(db.String(20), unique=True, nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=True)
    display_name = db.Column(db.String(100))
    profile_image_url = db.Column(db.String(200), default='default.jpg')
    last_seen = db.Column(db.DateTime, nullable=True)

class BlockList(db.Model):
    __tablename__ = 'block_list'
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.String(50), nullable=False)
    blocked_id = db.Column(db.String(50), nullable=False)

class Message(db.Model):
    __bind_key__ = 'messages'
    __tablename__ = 'message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(50), nullable=False)
    recipient_id = db.Column(db.String(50), nullable=False)
    text = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
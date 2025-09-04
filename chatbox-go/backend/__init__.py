import os
from flask import Flask
from flask_socketio import SocketIO
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from .models import db
from authlib.integrations.flask_client import OAuth

socketio = SocketIO(cors_allowed_origins="*")
jwt = JWTManager()
oauth = OAuth()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    
    app.config.from_mapping(
        SECRET_KEY='a_very_secret_key_for_production_12345',
        JWT_SECRET_KEY='another_super_secret_jwt_key_67890',
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{os.path.join(app.instance_path, 'users.db')}",
        SQLALCHEMY_BINDS={'messages': f"sqlite:///{os.path.join(app.instance_path, 'messages.db')}"},
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        GOOGLE_CLIENT_ID='865907751150-dbuit13oio1ininvmcteo71nqd88vak7.apps.googleusercontent.com',
        GOOGLE_CLIENT_SECRET='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'
    )

    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)

    CORS(app)
    db.init_app(app)
    jwt.init_app(app)
    oauth.init_app(app)
    socketio.init_app(app)

    oauth.register(
        name='google',
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        client_kwargs={'scope': 'openid email profile'}
    )

    with app.app_context():
        from .main import routes as main_routes
        from .api import routes as api_routes
        from .sockets import events

        app.register_blueprint(main_routes.main_bp)
        app.register_blueprint(api_routes.api_bp, url_prefix='/api')
        
        db.create_all()

    return app, socketio
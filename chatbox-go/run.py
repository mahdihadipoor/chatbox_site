from backend import create_app

app, socketio = create_app()

if __name__ == '__main__':
    cert_path = '/root/cert/chat.sky3d.ir/fullchain.pem'
    key_path = '/root/cert/chat.sky3d.ir/privkey.pem'

    socketio.run(
        app,
        host='0.0.0.0',
        port=443,
        certfile=cert_path,
        keyfile=key_path
    )
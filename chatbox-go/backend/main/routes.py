from flask import Blueprint, render_template, redirect, url_for, send_from_directory, current_app

main_bp = Blueprint('main_bp', __name__,
                    template_folder='../templates',
                    static_folder='../static')

@main_bp.route('/')
def index():
    return redirect(url_for('main_bp.login_page'))

@main_bp.route('/login')
def login_page():
    return render_template('login.html')

@main_bp.route('/panel')
def panel_page():
    return render_template('panel.html')

@main_bp.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.root_path + '/static/uploads', filename)
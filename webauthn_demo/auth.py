from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, login_user, logout_user
from .app import db
from .models import User

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = db.session.scalar(User.select().where(User.username == username))
        if not user:
            flash('Invalid username or password.')
            return redirect(url_for('auth.login'))
        if not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.')
            return redirect(url_for('auth.login'))
        if len(user.keys) > 0:
            session['user_id'] = user.id
            return redirect(url_for('webauthn.login'))
        login_user(user)
        return redirect(url_for('main.index'))
    return render_template('login.html')


@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User(username=username)
        user.password_hash = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully, you can login now.')
        return redirect(url_for('auth.login'))
    return render_template('register.html')


@bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

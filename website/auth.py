from flask import Blueprint, render_template, request, flash, redirect, url_for
import re
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)    #remembers the user, create a button!
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password or username, try again.', category='error')
        else:
            flash('User does not exist.', category='error')
    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirmation = request.form.get('password_confirmation')

        if not_existence(username, email):
            if check_username(username):
                if check_password(password):
                    if check_match(password, password_confirmation):
                        new_user = User(email=email, username=username, password=generate_password_hash(password, method='sha256'))
                        db.session.add(new_user)
                        db.session.commit()
                        flash('Account created!', category='success')
                        login_user(user, remember=True)
                        return redirect(url_for('views.home'))

    return render_template("sign_up.html", user=current_user)

def not_existence(username, email):
    user = User.query.filter_by(username=username).first()
    email = User.query.filter_by(email=email).first()
    if user:
        flash('Username already exists.', category='error')
        return False
    if email:
        flash('Email already exists.', category='error')
        return False
    return True


def check_username(username):
    if len(username) <= 3:
        flash('The username is too short, please create a new username.', category='error')
        return False
    if len(username) >= 9:
        flash('Username cannot be greater than 9 characters.', category='error')
        return False
    return True


def check_password(password):
    if len(password) < 6:
        flash('The password must be greater than 6 characters.', category='error')
        return False
    upper_case = "[A-Z]"
    if re.search(upper_case, password) is None:
        flash('The password does not containt uppercase.', category='error')
        return False
    lower_case = "[a-z]"
    if re.search(lower_case, password) is None:
        flash('The password does not contain lowercase.', category='error')
        return False
    symbols = "[!#$%&'()@*+,-./\^_`{|}~]"
    if re.search(symbols, password) is None:
        flash('The password does not containt special symbols.', category='error')
        return False
    numbers = "[1234567890]"
    if re.search(numbers, password) is None:
        flash('The password does not contain numbers.', category='error')
        return False
    return True


def check_match(password, password_confirmation):
    if password != password_confirmation:
        flash('The passwords do not match.', category='error')
        return False
    if password_confirmation == None:
        flash('Please enter password again.', category='error')
        return False
    return True
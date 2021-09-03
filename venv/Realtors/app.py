import os
import datetime
import sqlite3

from flask import Flask, flash, json, redirect, render_template, request, session, url_for, jsonify
from flask_login.utils import login_required
from flask_sqlalchemy import SQLAlchemy
from flask_session.__init__ import Session
from functools import wraps
from tempfile import mkdtemp
from sqlalchemy.orm import query
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length
from flask_migrate import Migrate, current
from config import Config
from sqlalchemy.inspection import inspect
from flask_marshmallow import Marshmallow   




basedir = os.path.abspath(os.path.dirname(__file__))
class Config(object):
    # ...
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = b'pz\x0e%\xdc\xb0\x91\x06\x0e\xb01\xf0u\xeb\xcc('

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class Serializer(object):

    def serialize(self):
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]

class User(UserMixin, db.Model, Serializer):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    type = db.Column(db.String(120))
    hash = db.Column(db.String(128))
    about = db.Column(db.String(200))
    display_name = db.Column(db.String(80), default='')
    phone_number = db.Column(db.String(140))
    portfolio = db.Column(db.String(140))
    listings = db.Column(db.String(140))


    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

    def check_password(self, password):
        return check_password_hash(self.hash, password)

    def to_json(self):
        return {
            'username': self.username,
        }

       
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User


class Feed(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(140))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    type = BooleanField('Are you a Realtor?')
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class EditProfile(FlaskForm):
    display_name = StringField('Name', validators=[DataRequired()])
    about = TextAreaField('About me', validators=[Length(min=0, max=200)])
    phone_number = StringField('Phone Number')
    save = SubmitField('Save')

class AddForm(FlaskForm):
    portfolio = StringField('Portfolio', validators=[DataRequired()])
    #price = StringField('Price', validators=[DataRequired()])
    #location = StringField('Location', validators=[DataRequired()])
    #transaction_type = TextAreaField('Transaction Type', validators=[Length(min=0, max=200)])
    save = SubmitField('Save')

login = LoginManager(app)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to SQLite database

login.login_view = 'login'

@app.route("/")
@app.route("/index")
@login_required
def index():
    return render_template("index.html")        
        
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if " " in form.username.data:
            flash('Ensure your username does not have any spaces')
            return redirect(url_for("register"))
        else:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            user.type = form.type.data
            db.session.add(user)
            db.session.commit()
            flash('You have successfully registered!')
            return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password. *Ensure each letter is capitalized correctly')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        current_user.display_name = current_user.username
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfile()
    if form.validate_on_submit():
        current_user.display_name = form.display_name.data
        current_user.about = form.about.data
        current_user.phone_number = form.phone_number.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.display_name.data = current_user.display_name
        form.about.data = current_user.about
        form.phone_number.data = current_user.phone_number
    return render_template('edit_profile.html', form=form)

@app.route('/user/<username>')
@login_required
def viewprofile(username):
    user = User.query.filter_by(username=username).first_or_404()

    return render_template('viewprofile.html', user=user)


@app.route('/view_search', methods=['GET', 'POST'])
@login_required
def view_search():
    ##realtorList = User.query.filter_by(type = 1).all()
    ##user_schema = UserSchema(many=True)
    ##realtors = user_schema.dump(realtorList)

    return render_template("view_search.html")

@app.route('/search')
@login_required
def search():
    realtorList = User.query.filter_by(type = 1).all()
    user_schema = UserSchema(many=True)
    realtors = user_schema.dump(realtorList)

    return jsonify(realtors)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    logout_user()

    # Redirect user to login form
    return redirect(url_for('index'))

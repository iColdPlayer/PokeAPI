import os
import json
import requests
from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bootstrap import Bootstrap
from flask_mongoengine import MongoEngine
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import Email, Length, InputRequired
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_caching import Cache


# using redis
config = {
    'DEBUG': True,
    'CACHE_TYPE': 'RedisCache',
    'CACHE_DEFAULT_TIMEOUT': 300
}

app = Flask(__name__)
db = MongoEngine()
app.config.from_mapping(config)
cache = Cache(app)
app.config['SECRET_KEY'] = 'hello from the other wife'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
Bootstrap(app)
db.init_app(app)


# set the limit
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=['100 per day']
)

app.config['MONGODB_SETTINGS'] = {
    'db': 'poke_db',
    'host': 'localhost',
    'port': 27017
}


class User(UserMixin, db.Document):
    meta = {'pokemon': 'pokemon'}
    email = db.StringField()
    password = db.StringField()


class Pokemon(db.Document):
    name = db.StringField()

    def to_json(self):
        return {
            'name': self.name,

        }


@login_manager.user_loader
def load_user(user_id):
    return User.objects(pk=user_id).first()


class RegForm(FlaskForm):
    email = StringField('email',  validators=[InputRequired(), Email(message='Invalid email'), Length(max=30)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=20)])


@app.route('/register', methods=['GET', 'POST'])
@cache.cached(timeout=50)
def register():
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            existing_user = User.objects(email=form.email.data).first()
            if existing_user is None:
                hashpass = generate_password_hash(form.password.data, method='sha256')
                user = User().save()
                login_user(user)
                return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegForm()
    if request.method == 'POST':
        if form.validate():
            check_user = User.objects(email=form.email.data).first()
            if check_user:
                if check_password_hash(check_user['password'], form.password.data):
                    login_user(check_user)
                    return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/', methods=['GET', 'POST'])
# cached
@cache.cached(timeout=50)
# request limit
@limiter.limit('10 per minute')
@login_required
def index():

    # https://pokeapi.co/api/v2/pokemon?offset=0&limit=10

    poke = [" ".join(i["name"].split("-")).title() for i in requests.get(
        f'https://pokeapi.co/api/v2/pokemon/?limit=-1'
    ).json()["results"]]

    print(poke[1:10])

    # insert one pokemon
    # x = Pokemon(name=poke[1])
    # x.save()
    # return jsonify(x.to_json())

    # InsertMany 0 - 9
    x = Pokemon.objects.insert([Pokemon(name=poke[0:10])])
    # json response
    return jsonify(x)

    # plain html respon
    # return render_template('index.html', pokemon=poke)


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


port = int(os.environ.get('PORT', 5000))
if __name__ == '__main__':
    app.run(threaded=True, port=port, debug=True)

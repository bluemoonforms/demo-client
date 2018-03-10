# -*- coding: utf-8 -*-
import os
import flask
import flask_login
import requests
import sqlite3
from flask_login.mixins import UserMixin
from wtforms import Form, PasswordField, StringField

from urllib.parse import urlparse, urljoin

login_manager = flask_login.LoginManager()

app = flask.Flask(__name__)
app.secret_key = 'o\x91\xc0\xcehh\xa5\xbf!\x8b\xcak2\xfe\x81\x89\xb6Ch9\x80\xcb6\xc7'
login_manager.init_app(app)
login_manager.login_view = "login"

DATABASE = '/app/database.db'


def get_db():
    """Create the database connection."""
    db = getattr(flask.g, '_database', None)
    if db is None:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        db = flask.g._database = conn
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection."""
    db = getattr(flask.g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database."""
    with app.app_context():
        db = get_db()
        with app.open_resource('/app/schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


def is_safe_url(target):
    """Just a safety check from flask snippets."""
    ref_url = urlparse(flask.request.host_url)
    test_url = urlparse(urljoin(flask.request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


class User(UserMixin):
    def __init__(self, data):
        self.data = {
            'id': data['id'],
            'username': data['username'],
            'license': data['license'],
            'token': data['token'],
        }
        self.id = data['id']
        self.username = data['username']
        self.license = data['license']
        self.token = data['token']

    @property
    def is_authenticated(self):
        return self.id is not None

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return not self.is_authenticated()

    def get_id(self):
        return '{}'.format(self.id)

    @staticmethod
    def find_user(license, username):
        cur = get_db().cursor()
        cur.execute(
            'SELECT id, username, license, token FROM users WHERE license=? AND username=?',
            (license, username)
        )
        results = cur.fetchone()
        return results

    @staticmethod
    def store_user(license, username, token):
        """Shove a user into the sqlite db."""
        results = User.find_user(license=license, username=username)
        if results:
            User.update(user_id=results['id'], token=token)
        else:
            User.create(license=license, username=username, token=token)
        results = User.find_user(license=license, username=username)
        return User(data=results)

    @staticmethod
    def update(user_id, token):
        conn = get_db()
        cur = conn.cursor()
        cur.execute('UPDATE users SET token=? WHERE id=?', (token, user_id))
        conn.commit()

    @staticmethod
    def create(license, username, token):
        conn = get_db()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (license, username, token) VALUES (?, ?, ?)', (
            license, username, token)
        )
        conn.commit()

    @staticmethod
    def get(user_id):
        cur = get_db().cursor()
        cur.execute('SELECT id, username, license, token FROM users WHERE id=?', (user_id,))
        results = cur.fetchone()
        if results:
            return User(data=results)


class LoginForm(Form):
    username = StringField('Username')
    license = StringField('License')
    password = PasswordField('Password')


@login_manager.user_loader
def load_user(user_id):
    """Find the user."""
    try:
        results = User.get(int(user_id))
    except (ValueError, TypeError):
        results = None
    return results


def login_user(license, username, password):
    """Take the login credentials and validate against oauth password grant server."""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Provider': 'legacy'
    }
    url = '{}/oauth/token'.format(os.getenv('OAUTH_CLIENT_URL'))
    payload = {
        'username': username,
        'password': password,
        'license': license,
        'grant_type': 'password',
        'client_id': os.getenv('OAUTH_CLIENT_ID'),
        'client_secret': os.getenv('OAUTH_CLIENT_SECRET')
    }
    response = requests.post(url, headers=headers, json=payload)
    data = response.json()
    if response.status_code == 200:
        user = User.store_user(license=license, username=username, token=data['access_token'])
        flask_login.login_user(user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """The login page for the application."""
    form = LoginForm(flask.request.form)
    if flask.request.method == 'POST' and form.validate():
        login_user(
            license=form.license.data,
            username=form.username.data,
            password=form.password.data
        )
        next = flask.request.args.get('next')

        if not is_safe_url(next):
            return flask.abort(400)

        return flask.redirect(next or flask.url_for('index'))
    return flask.render_template('login.html', form=form)


@app.route('/', methods=['GET'])
@flask_login.login_required
def index():
    """The primary index page for the application."""
    configuration = {
        'api_url': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'property_number': 6060,
        'access_token': flask_login.current_user.data['token']
    }
    context = {
        'static_url': os.getenv('LEASE_EDITOR_CDN', 'localhost:4201'),
        'configuration': configuration,
        'js_files': [
            'inline.bundle.js',
            'polyfills.bundle.js',
            'styles/styles.bundle.js',
            'vendor.bundle.js',
            'main.bundle.js',
        ]
    }

    return flask.render_template('index.html', context=context)


@app.route('/logout', methods=['GET'])
@flask_login.login_required
def logout():
    """Log the user out."""
    flask_login.logout_user()
    return flask.redirect(flask.url_for('login'))


@login_manager.unauthorized_handler
def unauthorized_handler():
    """Unauthorized handler."""
    return flask.redirect(flask.url_for('login'))

if __name__ == '__main__':
    # Only for debugging while developing
    app.run(host='0.0.0.0', debug=True, port=80)

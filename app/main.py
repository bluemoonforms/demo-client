# -*- coding: utf-8 -*-
import os
import flask
import flask_login
import requests
import json
import datetime
from flask_login.mixins import UserMixin
from wtforms import Form, PasswordField, StringField, IntegerField
from wtforms.validators import ValidationError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_
from urllib.parse import urlparse, urljoin

# Flask Setup

login_manager = flask_login.LoginManager()
app = flask.Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://{}:{}@{}:{}/{}'.format(
    os.getenv('DB_USER', 'demo'),
    os.getenv('DB_PASSWORD'),
    os.getenv('DB_HOST'),
    os.getenv('DB_PORT', '3306'),
    os.getenv('DB_NAME', 'demo'),
)
app.secret_key = 'o\x91\xc0\xcehh\xa5\xbf!\x8b\xcak2\xfe\x81\x89\xb6Ch9\x80\xcb6\xc7'
login_manager.init_app(app)
login_manager.login_view = "login"
db = SQLAlchemy(app)

BASE_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Provider': 'legacy'
}


def is_safe_url(target):
    """Just a safety check from flask snippets."""
    ref_url = urlparse(flask.request.host_url)
    test_url = urlparse(urljoin(flask.request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


def to_pretty_json(value):
    """Pretty json for template."""
    return json.dumps(
        value,
        sort_keys=True,
        indent=4,
        separators=(',', ': ')
    )

app.jinja_env.filters['tojson_pretty'] = to_pretty_json

# Forms


class LoginForm(Form):
    username = StringField('Username')
    license = StringField('License')
    password = PasswordField('Password')


def validate_lease_id(form, field):
    """API query to fetch lease number."""
    headers = BASE_HEADERS.copy()
    headers['Authorization'] = 'Bearer {}'.format(flask_login.current_user.token)
    url = '{}/api/lease/{}'.format(os.getenv('OAUTH_CLIENT_URL'), field.data)
    response = requests.get(url, headers=headers)
    if response.status_code == 404:
        raise ValidationError('Unable to find lease')
    if response.status_code != 200:
        raise ValidationError('Invalid lease id')


class SelectLeaseForm(Form):
    lease_id = IntegerField('Lease ID', [validate_lease_id])

# User utils and such


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    license = db.Column(db.String(40), nullable=False)
    token = db.Column(db.Text, nullable=False)

    def __repr__(self):
        """Representation."""
        return '<User %r>' % self.username

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


@login_manager.user_loader
def load_user(user_id):
    """Find the user."""
    try:
        results = User.query.get(int(user_id))
    except (ValueError, TypeError):
        results = None
    return results


def login_user(license, username, password):
    """Take the login credentials and validate against oauth password grant server."""
    headers = BASE_HEADERS.copy()
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
        user = User.query.filter(and_(User.username == username, User.license == license)).first()
        if not user:
            user = User(username=username, license=license, token=data['access_token'])
            db.session.add(user)
        else:
            user.token = data['access_token']
        db.session.commit()
        flask_login.login_user(user)


# Generic Utils


def get_property_number(token):
    """API query to fetch property number."""
    headers = BASE_HEADERS.copy()
    headers['Authorization'] = 'Bearer {}'.format(token)
    url = '{}/api/property'.format(os.getenv('OAUTH_CLIENT_URL'))
    response = requests.get(url, headers=headers)
    data = response.json()
    if response.status_code == 200:
        # Try to get the aptdb property number
        for prop in data['data']:
            if prop['unit_type'] == 'aptdb':
                return prop['id']
        # No apt db then just return the first one
        return data['data'][0]['id']


def get_settings(configuration):
    """Pulling this out to reuse for multiple endpoint."""
    js_files = [
        'inline.bundle.js',
        'polyfills.bundle.js',
        'main.bundle.js',
    ]
    css_files = [
        'styles/styles.bundle.css',
    ]

    if app.debug:
        js_files = [
            'inline.bundle.js',
            'polyfills.bundle.js',
            'styles/styles.bundle.js',
            'vendor.bundle.js',
            'main.bundle.js',
        ]
        css_files = []

    context = {
        'static_url': os.getenv('LEASE_EDITOR_CDN', 'localhost:4201'),
        'configuration': configuration,
        'js_files': js_files,
        'css_files': css_files
    }
    return context

# Views


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
    """The primary integration page for the application."""
    configuration = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': flask_login.current_user.token
    }
    context = get_settings(configuration=configuration)
    context['refresh'] = datetime.datetime.now().strftime('%Y%m%d%H%M')
    return flask.render_template('integration.html', context=context)


@app.route('/create', methods=['GET'])
@flask_login.login_required
def create():
    """An example of a lease create view only."""
    configuration = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': flask_login.current_user.token,
        'navigation': False,
        'view': 'create',
        'callBack': flask.url_for('callback', _external=True)
    }
    context = get_settings(configuration=configuration)
    context['refresh'] = datetime.datetime.now().strftime('%Y%m%d%H%M')
    return flask.render_template('integration.html', context=context)


@app.route('/badcreate', methods=['GET'])
@flask_login.login_required
def bad_create():
    """An example of a lease create view only."""
    configuration = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': flask_login.current_user.token,
        'navigation': False,
        'view': 'edit',
        'leaseId': 0,
        'callBack': flask.url_for('callback', _external=True)
    }
    context = get_settings(configuration=configuration)
    context['refresh'] = datetime.datetime.now().strftime('%Y%m%d%H%M')
    return flask.render_template('integration.html', context=context)


@app.route('/select', methods=['GET', 'POST'])
@flask_login.login_required
def select_lease():
    """Input a lease id then if it exists redirect to integration."""
    form = SelectLeaseForm(flask.request.form)
    message = None
    if flask.request.method == 'POST' and form.validate():
        return flask.redirect(flask.url_for('edit', lease_id=form.lease_id.data))
    return flask.render_template('select_lease.html', form=form, message=message)


@app.route('/edit/<int:lease_id>', methods=['GET'])
@flask_login.login_required
def edit(lease_id):
    """An example of a lease edit view only."""
    configuration = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': flask_login.current_user.token,
        'navigation': False,
        'view': 'edit',
        'leaseId': lease_id,
        'callBack': flask.url_for('callback', _external=True),
        'leaseData': {
            'standard': {
                'address': '123 Super Dr.'
            }
        }
    }
    context = get_settings(configuration=configuration)
    context['refresh'] = datetime.datetime.now().strftime('%Y%m%d%H%M')
    return flask.render_template('integration.html', context=context)


@app.route('/callback', methods=['POST'])
@flask_login.login_required
def callback():
    """An example of a callback for lease submission."""
    return flask.jsonify({'message': 'Success'})


@app.route('/docs', methods=['GET'])
@flask_login.login_required
def documentation():
    """Documentation lease edit view only."""
    configuration = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': 'TOKEN_GOES_HERE'
    }
    context = get_settings(configuration=configuration)
    context['create_view'] = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': 'TOKEN_GOES_HERE',
        'navigation': False,
        'view': 'create',
        'callBack': flask.url_for('callback', _external=True),
        'leaseData': None,
    }
    context['edit_view'] = {
        'apiUrl': os.getenv('API_URL', 'https://dev-lease.bluemoonformsdev.com'),
        'propertyNumber': get_property_number(flask_login.current_user.token),
        'accessToken': 'TOKEN_GOES_HERE',
        'navigation': False,
        'view': 'edit',
        'leaseId': 12345,
        'callBack': flask.url_for('callback', _external=True),
        'leaseData': None,
    }
    context['refresh'] = datetime.datetime.now().strftime('%Y%m%d%H%M')
    return flask.render_template('docs.html', context=context)


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
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(host='0.0.0.0', debug=True, port=80)

from flask import (
    Flask,
    request,
    Response,
    render_template,
    abort,
    make_response,
    redirect,
    url_for,
)
import sys
import hashlib
import base64
import uuid
import datetime
import os
import sys
import time
import pyotp
import bcrypt
from pprint import pformat
import dataset
import jwt
import functools
import logging
import gunicorn.app.base

app = Flask(__name__)
app.config.from_envvar('FLASK_CONFIG_FILE', silent=True)

db = dataset.connect(app.config['DB_PATH'])

logging.basicConfig(level=logging.DEBUG)
_logger = logging.getLogger(__name__)


class AuthInfo(object):
    cookiename = "AUTHCOOKIE"
    default_timeout = 2678400

    def __init__(self, token: bytes = None, data: dict = None):
        self._loadkeys()
        self._datacache = {}
        self.token = token
        self.max_age = self.default_timeout
        if data is not None:
            self.set_data(data)
        elif token is None:
            auth_cookie = request.cookies.get(self.cookiename)
            if auth_cookie is not None:
                auth_cookie = auth_cookie.encode("utf8")
                _logger.debug("create from cookie")
            else:
                auth_cookie = b""
                _logger.debug("no cookie set")
            self.token = auth_cookie
        _logger.debug("created, data {}".format(self.data))

    def _loadkeys(self):
        with open("jwtRS256.key") as f:
            self.privatekey = f.read()
        with open("jwtRS256.key.pub") as f:
            self.publickey = f.read()

    def set_cookie(self, response, **kwargs):
        _logger.debug("set cookie")
        self.update(
            useragent=request.headers["User-Agent"],
            exp=datetime.datetime.utcnow()
            + datetime.timedelta(seconds=self.default_timeout),
        )
        response.set_cookie("AUTHCOOKIE", self.token, max_age=self.max_age, **kwargs)

    def set_data(self, data, timeout=None):
        _logger.debug("set data: {}".format(data))
        if timeout is None:
            timeout = self.default_timeout
        if data is None or len(data) == 0:
            self.max_age = 0
        else:
            self.max_age = timeout
        self.token = jwt.encode(data, self.privatekey, algorithm="RS256")
        self._datacache = {}

    def get_data(self):
        try:
            _logger.info("decode")
            self._datacache = jwt.decode(self.token, self.publickey, algorithm="RS256")
            if "exp" in self._datacache:
                self.max_age = (
                    datetime.datetime.fromtimestamp(self._datacache["exp"])
                    - datetime.datetime.utcnow()
                )
        except Exception as e:
            _logger.exception("decoding error")
            self._datacache = {}
        finally:
            return self._datacache

    def update(self, **kwargs):
        if "_data" in kwargs:
            arguments = kwargs["_data"]
        else:
            arguments = kwargs
        tmpdata = self.data
        tmpdata.update({k: v for k, v in arguments.items() if v is not None})
        for k, v in arguments.items():
            if v is None and k in tmpdata:
                del tmpdata[k]
        self.set_data(tmpdata)

    @property
    def isset(self):
        return len(self.data) > 0

    @property
    def data(self):
        if len(self._datacache) == 0:
            self.get_data()
        return self._datacache

def inject_ai(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        ai = AuthInfo()
        result = func(*args, ai=ai, **kwargs)
        response = make_response(result)
        ai.set_cookie(response)
        return response
    return decorator


def authenticate(ai):
    if "fwd" in ai.data:
        response = make_response(redirect(ai.data["fwd"]))
    else:
        response = make_response("success")
    ai.set_cookie(response)
    response.headers["X-Auth"] = ai.token
    response.headers["X-User"] = ai.data["username"]
    return response

@app.route("/logout", methods=["POST", "GET"])
@inject_ai
def do_logout(ai):
    ai.set_data({})
    return "logged out", 401


@app.route("/login", methods=["POST", "GET"])
@inject_ai
def do_login(ai):
    if "fwd" in request.values:
        ai.update(fwd=request.values["fwd"])
    if ai.isset and 'username' in ai.data:
        _logger.debug("login using cookie")
        return authenticate(ai)

    if request.method == "GET":
        if ai.isset and "otp" in ai.data and "uuid" in ai.data["otp"]:
            return render_template("otp.html")
        return render_template("login.html")

    users = db["users"]
    otp_preauth = db["otpstep"]
    retry = ai.data.get("retry", 0)
    _logger.info("current retrycount: %s", retry)
    if retry >= 3:
        _logger.info("exceeded retry limit")
        ai.set_data({})
        return "failed", 401

    if ai.isset and "otp" in ai.data and "uuid" in ai.data["otp"]:
        _logger.info("checking otp")
        entry = otp_preauth.find_one(uuid=ai.data["otp"]["uuid"])
        if entry is None or entry["timestamp"] < time.time():
            _logger.info("entry for otp to old")
            ai.update(otp=None)
            return redirect(url_for("do_login"))

        user = users.find_one(username=entry["username"])
        totp = pyotp.TOTP(user["otp"])
        if not totp.verify(request.form["otp"], valid_window=3):
            _logger.info("otp failed")
            ai.update(retry=ai.data.get("retry", 0) + 1)
            return redirect(url_for("do_login"))

        _logger.info("otp ok")
        ai.update(otp=None, username=entry["username"])
        return authenticate(ai)

    try:
        user = request.form["username"]
        pwd = request.form["password"].encode("utf8")
    except KeyError:
        return redirect(url_for("do_login"))

    appusers = db["appuser"]
    validuser = users.find_one(username=user)
    validappuser = appusers.find(username=user)
    if validuser is not None:
        if not bcrypt.checkpw(pwd, validuser["password"]):
            ai.update(otp=None)
            ai.update(retry=ai.data.get("retry", 0) + 1)
            return redirect(url_for("do_login"))

        otp_preauth = db["otpstep"]
        preauth_id = uuid.uuid4().hex
        preauth_entry = {
            "username": user,
            "uuid": preauth_id,
            "timestamp": time.time() + 60,
        }
        ai.update(_data={"otp": {"uuid": preauth_entry["uuid"]}})
        otp_preauth.delete(username=user)
        otp_preauth.insert(preauth_entry)
        return redirect(url_for("do_login"))

    for appuser in validappuser:
        if bcrypt.checkpw(pwd, validuser["password"]):
            _logger.debug("success appuser")
            return authenticate(ai)

    time.sleep(1)
    return redirect(url_for("do_login"))


@app.route("/auth")
def hello():
    _logger.debug(request.headers)
    ai = AuthInfo()
    if ai.isset and 'username' in ai.data:
        _logger.debug("login using cookie")
        return authenticate(ai)
    _logger.debug("check failed")
    _logger.debug("forward to loginpage")
    abort(401)


@app.errorhandler(404)
def page_not_found(error):
    return redirect(url_for('do_login'))

class StandaloneApplication(gunicorn.app.base.BaseApplication):

    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        config = {key: value for key, value in self.options.items()
                       if key in self.cfg.settings and value is not None}
        print(1)
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

if __name__ == "__main__":

    if len(sys.argv) == 2 and sys.argv[1] == "adduser":
        username = input("Username: ")
        import getpass
        import pyqrcode

        password = getpass.getpass("Password: ")
        otp_secret = pyotp.random_base32()
        bcrypt_rounds = int(os.getenv('BCRYPT_ROUNDS', '12'))
        user = {
            "username": username,
            "password": bcrypt.hashpw(password.encode("utf8"), bcrypt.gensalt(bcrypt_rounds)),
            "otp": otp_secret,
        }
        db["users"].insert(user)
        otp = pyotp.totp.TOTP(otp_secret).provisioning_uri(
            username, issuer_name=os.getenv('TOTP_ISSUER', 'auth')
        )
        print(pyqrcode.create(otp).terminal())
    else:
        port = os.getenv('GUNICORN_PORT', '9999')
        options = {
            'bind': '%s:%s' % ('0.0.0.0', port),
        }
        StandaloneApplication(app, options).run()

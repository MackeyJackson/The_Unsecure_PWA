from flask import Flask
from flask import render_template
from flask import request
from flask import redirect
from flask import jsonify,abort, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from logging.handlers import RotatingFileHandler
import datetime
import os
from datetime import timedelta
from urllib.parse import urlparse
import secrets
from urllib.parse import urlparse, urljoin
import html 
import pyotp
import qrcode
import io
import base64
import time
from flask_talisman import Talisman


#File Imports
import user_management as dbHandler
from SecurityFeatureModules import SanitisationAndValidation as SAV
from SecurityFeatureModules import HashAndSalt as HAS
#--- Testing zone ---


#--- end of zone ---
# Code snippet for logging a message
# app.logger.critical("message")

app = Flask(__name__)
#Talisman(app, strict_transport_security=True)
#session managment
app.secret_key = os.urandom(32) #signs the session to prevent tampering
app.permanent_session_lifetime = timedelta(minutes=60) #cookie expiriy 

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True, #requires HTTPs
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60)
)

#logging for API
handler = RotatingFileHandler('logs/ApiLog.txt', maxBytes=1000000, backupCount=3)
handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
#invalid forwardng and redirecting
from urllib.parse import urlparse

def SafeUrl(TargetUrl):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, TargetUrl))
    
    return (
        test_url.scheme == 'https' and
        ref_url.netloc == test_url.netloc
    )

#rate limiting API
limiter = Limiter(get_remote_address, app=app, default_limits=["2000 per day", "500 per hour", "500 per minute"])
#Input validation and sanitisation
DomainWhitelist = "localhost:8080"

@app.before_request
def checkReferrer():
    referrer = request.referrer
    if referrer:
        referrer_domain = urlparse(referrer).netloc
        # Check if the referrer is from a different domain
        if referrer_domain != DomainWhitelist:
            session.clear()
            app.logger.info(f"Suspicious referrer detected from domain: {referrer_domain}")
            return redirect("/")
#CSP
cspPolicy = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "  # AJAX requests
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self';"
)
@app.after_request
def CSPheader(response):
    # CSP header
    cspPolicy = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "  # AJAX requests
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'self';"
)
    response.headers['Content-Security-Policy'] = cspPolicy
    return response
Talisman(app, content_security_policy=cspPolicy)
"""
@app.route("/success.html", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
def addFeedback():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        return redirect(url, code=302)
    if request.method == "POST":
        feedback = request.form["feedback"]
        print(feedback)
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("/success.html", state=True, value="Back")
"""
#2FA
@app.route("/2fa", methods=["GET"])
def factorAuth():
    if 'username' not in session:
        return redirect(url_for('postLogin', next=request.path))
    if session.get('authenticated'):
        return redirect(url_for('successPage'))
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    #2fa
    username = session['username']
    secret = dbHandler.retrieveUserSecret(username)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name="SecurePWACompany")
    #makeQRimage
    QrImg = qrcode.make(uri)
    buf = io.BytesIO()
    QrImg.save(buf, format='PNG')
    QrImg = base64.b64encode(buf.getvalue()).decode("ascii")
    #load actual page
    return render_template('2fa.html', csrf_token=token, qr_code_data=QrImg)


@app.route("/2fa", methods=["POST"])
@limiter.limit("100 per minute")
def TwoFAPage():
    form_token = request.form.get("csrf_token")
    session_token = session.get("csrf_token")
    if not form_token or form_token != session_token:
        print("csrf error")
        NewToken = secrets.token_hex(16)
        session['csrf_token'] = NewToken
        return jsonify({"error": "CSRF token mismatch", "csrf_token": NewToken}), 400 #cancels the form submission
    session.pop("csrf_token", None)
    NewToken = secrets.token_hex(16)
    session['csrf_token'] = NewToken
    AllowedParams = ['otp', 'csrf_token', 'next']
    data = request.form.to_dict()
    for param in data:
        if param not in AllowedParams:
            return jsonify({"error": f"Invalid parameter: {param}"}), 400
    username = session['username']
    secret = dbHandler.retrieveUserSecret(username)
    code = request.form["otp"]
    iscode = SAV.onlynum(code)
    nextPage = request.form.get("next")
    if iscode == False:
        return jsonify({"error": "Only numbers are allowed", "csrf_token": NewToken}), 401
    if pyotp.TOTP(secret).verify(code):
        session['authenticated'] = True
        if nextPage and SafeUrl(nextPage):
            return redirect(nextPage)
        return redirect(url_for("successPage"))
    else:
        return jsonify({"error": "Incorrect Code", "csrf_token": NewToken}), 401
    
    


@app.route("/signup", methods=["GET"])
def GetSignUp():
    #generate CSRF
    state=False
    if session.get('authenticated'):
        state=True
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    #load actual page
    return render_template('signup.html', csrf_token=token, state=state)

# POST for sending form to server
@app.route("/signup", methods=["POST"])
@limiter.limit("100 per minute")
def signupPage():
    #CSRF TOKEN
    form_token = request.form.get("csrf_token")
    session_token = session.get("csrf_token")
    if not form_token or form_token != session_token:
        print("csrf error")
        NewToken = secrets.token_hex(16)
        session['csrf_token'] = NewToken
        return jsonify({"error": "CSRF token mismatch", "csrf_token": NewToken}), 400 #cancels the form submission
    session.pop("csrf_token", None)
    NewToken = secrets.token_hex(16)
    session['csrf_token'] = NewToken
    #whitelist APi Parameters
    AllowedParams = ['username', 'password','email', 'csrf_token', 'next']
    data = request.form.to_dict()
    for param in data:
        if param not in AllowedParams:
            return jsonify({"error": f"Invalid parameter: {param}"}), 400
    username = request.form["username"]
    password = request.form["password"]
    email = request.form["email"]
    #Logging
    ip = request.remote_addr
    now = datetime.datetime.now()
    app.logger.info(f"Sign Up attempt sent to server with parameters: Username({username}) | Request from IP: {ip} at time: {now}")
    #validation and sanitization
    try:
        SAV.ValidateName(username) 
        SAV.validatePassword(password)
        SAV.CheckEmail(email)
    except Exception as e:
        #errormessage = str(e)
        return jsonify({"error": f"Unauthorised Acess{e}", "csrf_token": NewToken}), 401
    # check if user already exists
    AccountsWUsername = dbHandler.usernameExists(username)
    print(AccountsWUsername)
    if AccountsWUsername == None:
        return jsonify({"error": "Username Already Exists", "csrf_token": NewToken}), 401
    password = HAS.SaltAndHash(password)
    OtpSecret = pyotp.random_base32()
    dbHandler.insertUser(username,password,OtpSecret,email)
    nextPage = request.form.get("next")
    print(nextPage, SafeUrl(nextPage))
    session.clear()
    session['username'] = username
    if nextPage and SafeUrl(nextPage):
            return redirect(nextPage)
    return redirect(url_for("successPage"))
   

#Following REST
@app.route("/", methods=["GET"])
def getpage():
    #generate CSRF
    state=False
    if session.get('authenticated'):
        state=True
    token = secrets.token_hex(16)
    session['csrf_token'] = token
    #load actual page
    return render_template('index.html', csrf_token=token,state=state)

# POST for sending form to server
@app.route("/", methods=["POST"])
@limiter.limit("100 per minute")
def postLogin(): 
    #CSRF TOKEN
    form_token = request.form.get("csrf_token")
    session_token = session.get("csrf_token")
    if not form_token or form_token != session_token:
        NewToken = secrets.token_hex(16)
        session['csrf_token'] = NewToken
        return jsonify({"error": "CSRF token mismatch (login)", "csrf_token": NewToken}), 400 #cancels the form submission
    session.pop("csrf_token", None)
    #generate new CSRFT for future form submissions
    NewToken = secrets.token_hex(16)
    session['csrf_token'] = NewToken
    #whitelist APi Parameters
    AllowedParams = ['username', 'password', 'csrf_token', 'next']
    data = request.form.to_dict()
    for param in data:
        if param not in AllowedParams:
            return jsonify({"error": f"Invalid parameter: {param}"}), 400
    username = request.form["username"]
    password = request.form["password"]
    #Logging
    ip = request.remote_addr
    now = datetime.datetime.now()
    app.logger.info(f"Log in attempt sent to server with parameters: Username({username}), Password(**Hidden**) | Request from IP: {ip} at time: {now}")
    #validation and sanitization
    try:
        SAV.ValidateName(username) 
        SAV.validatePassword(password)
    except Exception as e:
        #errormessage = str(e)
        return jsonify({"error": "Unauthorised Acess", "csrf_token": NewToken}), 401
    # Login attempt
    isLoggedIn = dbHandler.retrieveUserPassword(username)
    time.sleep(0.5)
    if isLoggedIn != False:
        PasswordCheck = HAS.check_password(password, isLoggedIn)
    else:
        return jsonify({"error": "Incorrect Username or Password", "csrf_token": NewToken}), 401
    print("Request args:", request.args)
    nextPage = request.form.get("next")
    if PasswordCheck:
        session.clear()
        session['username'] = username
        #get secret
        #dbHandler.listFeedback()
        #return redirect("/success", 302)  # Successful login, redirect to a success page
        #return redirect(url_for("successPage"))
        print(nextPage, SafeUrl(nextPage))
        if nextPage and SafeUrl(nextPage):
            return redirect(nextPage)
        return redirect(url_for("factorAuth"))
    else:
        return jsonify({"error": "Incorrect Username or Password", "csrf_token": NewToken}), 401
# Success page after login (GET request)
@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("postLogin"))
@app.route("/success", methods=["GET"])
def successPage():
    if 'username' not in session:
        return redirect(url_for('postLogin', next=request.path))
    if not session.get('authenticated'):
        return redirect(url_for('factorAuth'))
    user = session.get('username', 'Guest')
    #html escape
    user = html.escape(user) 

    token = secrets.token_hex(16)
    session['csrf_token'] = token
    #get comments
    PrevComments = dbHandler.GetComments()
    #load actual page
    return render_template("/success.html", PrevComments = PrevComments, csrf_token=token, value=user, state=True)

@app.route("/success", methods=["POST"])
def comment():
    form_token = request.form.get("csrf_token")
    session_token = session.get("csrf_token")
    if not form_token or form_token != session_token:
        print("csrf error")
        NewToken = secrets.token_hex(16)
        session['csrf_token'] = NewToken
        return jsonify({"error": "CSRF token mismatch", "csrf_token": NewToken}), 401
    session.pop("csrf_token", None)
    NewToken = secrets.token_hex(16)
    session['csrf_token'] = NewToken
    AllowedParams = ['feedback', 'csrf_token', 'next', 'action', 'comment_id', 'new_feedback']
    data = request.form.to_dict()
    for param in data:
        if param not in AllowedParams:
            return jsonify({"error": f"Invalid parameter: {param}"}), 400
    if request.form.get("action") == "new":
        username = session['username']
        comment = request.form["feedback"]
        username = html.escape(username)
        comment = html.escape(comment)
        try:
            SafeComment = SAV.validateComment(comment)
        except Exception as e:
            #errormessage = str(e)
            return jsonify({"error": f"{e}", "csrf_token": NewToken}), 401
        if SafeComment:
            dbHandler.InsertComment(comment, username)
            return redirect(url_for('successPage'))
        else:
            return jsonify({"error": "Invalid Comment", "csrf_token": NewToken}), 401
    if request.form.get("action") == "edit":
        new_feedback = request.form.get("new_feedback")
        try:
            SafeComment = SAV.validateComment(new_feedback)
        except Exception as e:
            #errormessage = str(e)
            return jsonify({"error": f"{e}", "csrf_token": NewToken}), 401
        comment_id = request.form.get("comment_id")
        new_feedback = html.escape(new_feedback)
        if dbHandler.EditComment(comment_id, new_feedback, session['username']):
            return redirect(url_for('successPage'))
        else:
            return jsonify({"error": "You are not authorized to edit this comment.", "csrf_token": NewToken}), 403
    if request.form.get("action") == "delete":
        comment_id = request.form.get("comment_id")
        if dbHandler.DeleteComment(comment_id, session['username']):
            return redirect(url_for('successPage'))
        else:
            return jsonify({"error": "You are not authorized to delete this comment.", "csrf_token": NewToken}), 403

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(host="0.0.0.0", port=8080, ssl_context=("certE.pem", "keyE.pem"))
#UPDATE CSRF ON FRONT END MIGHT BE ISSUE -- maybe not

#todo
"""
DONE 0.get the JS to display the errors & make flask not
DONE 1.fix the not restfulness of the error message in login
DONE 2.JS should just show why its wrong and if they mnipulate the code to submit the form anyways, the server side check denys them without an error 401 unorthorised
DONE 3.Using whitelists to specify which parameters are allowed in requests for api
DONE 4.Monitoring and logging API activity to check for attacks
DONE x.Rate limiting
DONE 6. Implement session managemnt
DONE 7. Implement 2fa
DONE 8 DONE CSRF, Race conditions and DONE CSP
8.Add features to DONE sign in, DONE log out and comment functionality

sign in
DONE 1. no duplicate usernames
DONE 2. race conditions
DONE 3. bcrypt

ALL THATS LEFT:
DONE comment functionality
DONE race conditions
"""
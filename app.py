import os
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import HTTPException
from itsdangerous import URLSafeTimedSerializer
import bleach
from config import SECRET_KEY  # type: ignore
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from alembic import op
import sqlalchemy as sa
from forms import RegistrationForm, LoginForm, ChangeEmailForm, ResetPasswordForm, ForgotPasswordForm, FeedbackForm, ContactForm, ChangePasswordForm, ProfileForm, FriendRequestForm, AcceptFriendRequestForm, ResendConfirmationForm
import re



app = Flask(__name__)

limiter = Limiter(
    get_remote_address,  # You can also use a custom function to identify clients
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Set default rate limits
)

SECRET_KEY = os.getenv('SECRET_KEY')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')

# App configurations
app.config['SECRET_KEY'] = SECRET_KEY
csrf = CSRFProtect(app)
app.secret_key = os.urandom(24)

# Setup database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Honda159753852*@localhost/db_ghosty_ware'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_TIMEOUT'] = 30
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'ghostshadow9111993@gmail.com'
app.config['MAIL_PASSWORD'] = "ojit dfmg oele jqou"
app.config['MAIL_DEFAULT_SENDER'] = 'ghostshadow9111993@gmail.com'

mail = Mail(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

# Models
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False) 
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_out_until = db.Column(db.DateTime, nullable=True)
    profile_photo = db.Column(db.String(150), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    is_online = db.Column(db.Boolean, default=False)
    email_confirmation_sent_at = db.Column(db.DateTime, nullable=True, default=None) 

    # Relationship for friend requests sent by the user
    sent_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.sender_id', backref='sender', lazy=True)
    
    # Relationship for friend requests received by the user
    received_friend_requests = db.relationship('FriendRequest', foreign_keys='FriendRequest.receiver_id', backref='receiver', lazy=True)

class FriendRequest(db.Model):
    __tablename__ = 'friend_request'  # Set a name for this table
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    accepted = db.Column(db.Boolean, default=False)

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='feedbacks')

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<User {self.username}>'


# Alembic migration identifiers
revision = '3f0816e98449'  # Update with your actual revision id
down_revision = None  # Update with your previous migration id
branch_labels = None
depends_on = None

def upgrade():
    # Add the is_online column
    op.add_column('user', sa.Column('is_online', sa.Boolean(), nullable=True))

def downgrade():
    # Remove the is_online column
    op.drop_column('user', 'is_online')


with app.app_context():
    db.create_all()

@app.route('/is_admin_login', methods=['GET', 'POST'])
def is_admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):  # Assuming you're using bcrypt for password hashing
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin  # Set is_admin in the session
            flash('Logged in successfully!', 'success')
            return redirect(url_for('view_messages'))  # Redirect to the messages page if successful
        else:
            flash('Invalid username or password', 'danger')

    return render_template('admin_login.html')


@app.route('/send_friend_request/<int:receiver_id>', methods=['POST'])
def send_friend_request(receiver_id):
    if 'user_id' not in session:
        logging.warning('User not logged in. Attempted to send friend request.')
        return jsonify(success=False, message='You need to log in to send friend requests.'), 403

    sender_id = session['user_id']
    
    # Check if a friend request already exists
    existing_request = FriendRequest.query.filter_by(sender_id=sender_id, receiver_id=receiver_id).first()
    if existing_request:
        logging.info(f'Friend request already exists from {sender_id} to {receiver_id}.')
        return jsonify(success=False, message='You have already sent a friend request to this user.'), 200

    # Create and add the new friend request
    new_request = FriendRequest(sender_id=sender_id, receiver_id=receiver_id)
    db.session.add(new_request)

    try:
        db.session.commit()
        logging.info(f'Friend request sent from {sender_id} to {receiver_id}.')
        return jsonify(success=True, message='Friend request sent!'), 200
    except Exception as e:
        logging.error(f'Error occurred while sending friend request from {sender_id} to {receiver_id}: {e}')
        db.session.rollback()  # Roll back in case of an error
        return jsonify(success=False, message='An error occurred while sending the friend request. Please try again.'), 500
    

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in to accept friend requests.', 'danger')
        return redirect(url_for('login'))

    # Find the friend request by ID
    friend_request = FriendRequest.query.get(request_id)
    if friend_request is None:
        flash('Friend request not found.', 'warning')
        return redirect(url_for('profile'))

    # Check if the logged-in user is the receiver of the request
    if friend_request.receiver_id != session['user_id']:
        flash('You cannot accept this friend request.', 'danger')
        return redirect(url_for('profile'))

    # Logic to create a new friendship
    new_friendship = Friendship(user_id=friend_request.receiver_id, friend_id=friend_request.sender_id)
    db.session.add(new_friendship)

    # Remove the friend request
    db.session.delete(friend_request)

    try:
        db.session.commit()
        flash('Friend request accepted!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while accepting the friend request. Please try again.', 'danger')

    return redirect(url_for('profile'))  # Ensure to redirect to profile after processing

def accept_friend_request(request_id):
    friend_request = FriendRequest.query.get(request_id)
    if friend_request and friend_request.receiver_id == session['user_id']:
        friend_request.accepted = True
        db.session.commit()
        flash('Friend request accepted!', 'success')
    else:
        flash('Friend request not found or not authorized.', 'error')
    return redirect(url_for('profile'))

@app.route('/friends')
def friends():
    # Assuming you're using Flask-Login to get the current user
    current_user = User.query.get(current_user.id)
    
    # Retrieve all friends for the current user
    friends_list = current_user.get_friends()
    
    return render_template('profile.html', friends=friends_list)


@app.errorhandler(429)
def ratelimit_handler(e: HTTPException):
    return jsonify(error="Rate limit exceeded, please try again later."), 429

# Custom rate-limited resource
@app.route("/api/resource")
@limiter.limit("10 per minute")  # Custom rate limit
def limited_resource():
    return jsonify({"message": "This is a rate-limited resource."})

def is_confirmation_expired(user):
    # Define how long the confirmation is valid for (e.g., 24 hours)
    confirmation_timeout = timedelta(hours=24)
    
    if user.email_confirmation_sent_at is None:
        logging.debug("Email confirmation was never sent.")
        return True  # Treat as expired if never sent
    
    expiration_time = user.email_confirmation_sent_at + confirmation_timeout
    is_expired = datetime.utcnow() > expiration_time
    
    logging.debug(f"Checking expiration: current time is {datetime.utcnow()}, "
                  f"expiration time is {expiration_time}, expired: {is_expired}.")
    
    return is_expired

def send_confirmation_email(user):
    token = s.dumps(user.email, salt='email-confirm-salt')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Please Confirm Your Email"
    body = f"Please confirm your email by clicking the following link: {confirm_url}"
    
    try:
        send_email(user.email, subject, body)  # Send the body as plain text instead of using an HTML template
    except Exception as e:
        print(f"Failed to send confirmation email: {e}")

def send_email(to, subject, body):
    msg = Message(subject, recipients=[to])
    msg.body = body
    try:
        mail.send(msg)
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route("/api/login", methods=["GET", "POST"])
@limiter.limit("8 per minute")  # Limit login attempts
def login():
    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            remember = form.remember.data

            user = User.query.filter_by(username=username).first()

            # Check if the user is locked out
            if user and user.locked_out_until and user.locked_out_until > datetime.utcnow():
                return jsonify({"message": "Your account is temporarily locked. Please try again later."}), 403

            if user:
                if bcrypt.check_password_hash(user.password, password):
                    if not user.confirmed:
                        if is_confirmation_expired(user):
                            # Resend confirmation email if the email confirmation has expired
                            try:
                                send_confirmation_email(user)  # Attempt to send a new confirmation email
                                user.email_confirmation_sent_at = datetime.utcnow()  # Update the timestamp
                                db.session.commit()
                                return jsonify({"message": "A new confirmation email has been sent. Please confirm your email to log in."}), 403
                            except Exception as e:
                                print(f"Failed to send confirmation email: {e}")  # Log the error
                                return jsonify({"message": "An error occurred while sending the confirmation email. Please try again later."}), 500

                        return jsonify({"message": "Please confirm your email address before logging in."}), 403

                    # Successful login
                    user.failed_attempts = 0  # Reset failed attempts
                    user.locked_out_until = None
                    user.is_online = True
                    db.session.commit()

                    session['user_id'] = user.id
                    if remember:
                        session.permanent = True  # Keep session active if "Remember Me" is checked

                    return jsonify({"message": "Logged in successfully!", "redirect": url_for('home')}), 200
                else:
                    # Increment failed attempts
                    user.failed_attempts += 1

                    # Lock the account after 3 failed attempts
                    if user.failed_attempts >= 3:
                        user.locked_out_until = datetime.utcnow() + timedelta(minutes=7)

                    db.session.commit()  # Commit changes after updating failed attempts

                    return jsonify({"message": "Invalid username or password."}), 403
            else:
                return jsonify({"message": "Invalid username or password."}), 403  # Explicitly handle user not found

    # Render the login form for GET requests
    return render_template('login.html', form=form)

logging.basicConfig(level=logging.DEBUG)

@app.route("/api/resend_confirmation", methods=["POST"])
@limiter.limit("5 per minute")  # Example limit
def resend_confirmation():
    form = ResendConfirmationForm()  # Create a form to handle the email input
    if form.validate_on_submit():
        email = form.email.data
        logging.debug(f"Email received for confirmation resend: {email}")
        user = User.query.filter_by(email=email).first()

        if user:
            logging.debug(f"User found: {user}")
            if not user.confirmed:
                if is_confirmation_expired(user):
                    try:
                        send_confirmation_email(user)  # Send a new confirmation email
                        return jsonify({"message": "A new confirmation email has been sent. Please check your inbox."}), 200
                    except Exception as e:
                        logging.error(f"Error sending confirmation email: {e}")
                        return jsonify({"message": "Failed to send confirmation email. Please try again later."}), 500
                else:
                    logging.debug("Confirmation email has not expired.")
                    return jsonify({"message": "Your confirmation email has not yet expired. Please check your email."}), 403
            else:
                logging.debug("User email is already confirmed.")
                return jsonify({"message": "Your email is already confirmed."}), 403
        else:
            logging.debug("No user found with this email.")
            return jsonify({"message": "No user found with this email."}), 404

    logging.debug("Invalid request made.")
    return jsonify({"message": "Invalid request."}), 400
def is_confirmation_expired(user):
    confirmation_timeout = timedelta(hours=24)  # or your chosen timeout
    if user.email_confirmation_sent_at is None:
        return True  # Or False, depending on your logic for missing values
    return datetime.utcnow() > (user.email_confirmation_sent_at + confirmation_timeout)


def rate_limit_key():
    # Example: Use the username or API key for rate-limiting
    return request.headers.get('X-API-KEY')

@app.before_request
def before_request():
    # Set last_activity time to now if not already set
    if 'last_activity' not in session:
        session['last_activity'] = datetime.now(timezone.utc)
    else:
        # Update last_activity to the current time
        session['last_activity'] = datetime.now(timezone.utc)

# Rate-limited resource with custom key (API key based)
@app.route("/api/user-data")
@limiter.limit("20 per hour", key_func=lambda: request.headers.get('X-API-KEY'))  # Custom rate-limiting key
def user_data():
    return jsonify({"message": "User-specific rate-limited resource."})



def session_timeout(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if last_activity is in session
        if 'last_activity' in session:
            # Calculate session duration
            session_duration = (datetime.now(timezone.utc) - session['last_activity']).total_seconds() / 60.0
            if session_duration > app.config['SESSION_TIMEOUT']:
                session.pop('user_id', None)  # Log out the user
                flash('Your session has expired. Please log in again.', 'warning')
                return redirect(url_for('login'))

        # Update last activity time to now
        session['last_activity'] = datetime.now(timezone.utc)  # Ensure it's timezone-aware
        return f(*args, **kwargs)

    return decorated_function

# Home page with session timeout
@app.route("/")
@session_timeout
def home():
    session_duration = (datetime.now(timezone.utc) - session['last_activity']).total_seconds() / 60.0
    return render_template('index.html', is_admin=is_admin())

@app.route('/is_admin/dashboard')
@session_timeout
def admin_dashboard():
    if not is_admin():
        flash("You do not have permission to access this page.", "error")
        return redirect(url_for('is_admin_login'))
    return render_template('admin_dashboard.html')

@app.context_processor
def context_processor():
    return dict(is_admin=is_admin)

def is_admin():
    return 'is_admin' in session

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request", sender='ghostshadow9111993@gmail.com', recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"

            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash(f'Failed to send email: {str(e)}', 'error')
        else:
            flash('No account found with that email address.', 'error')

        return redirect(url_for('login'))

    return render_template('forgot_password.html', form=form)


s = URLSafeTimedSerializer(app.secret_key)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)

            msg = Message("Password Reset Request", sender='ghostshadow9111993@gmail.com', recipients=[email])
            msg.body = f"To reset your password, visit the following link: {reset_url}"

            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash(f'Failed to send email: {str(e)}', 'error')
        else:
            flash('No account found with that email address.', 'error')

        return redirect(url_for('profile'))

    return render_template('change_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPasswordForm()

    try:
        email = s.loads(token, salt='password-reset-salt', max_age=900)  # 15 minutes expiration
    except Exception as e:
        flash('The reset link is invalid or has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))

    if form.validate_on_submit():
        new_password = form.new_password.data
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

        user = User.query.filter_by(email=email).first()
        if user:
            try:
                user.password = hashed_password
                db.session.commit()
                flash('Your password has been updated successfully!', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating password: {str(e)}', 'danger')
        else:
            flash('User not found.', 'danger')

    # Log form errors if validation fails
    if form.errors:
        print("Form Errors:", form.errors)

    return render_template('reset_password.html', form=form, token=token)

import logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Log debug information for the registration process
        logging.debug(f"Attempting to register user: {username}, {email}")

        # Username validation and checks
        if not re.match("^[A-Za-z0-9]*$", username):
            flash("Username can only contain letters and numbers.", "danger")
            return redirect(url_for('register'))

        if username in banned_usernames:
            flash("This username is not allowed.", "danger")
            return redirect(url_for('register'))

        # Duplicate email and username checks
        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please use a different email.", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username already taken. Please choose a different username.", "danger")
            return redirect(url_for('register'))

        # Hash the password and add the new user
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, confirmed=False)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Email confirmation setup
            token = s.dumps(email, salt='email-confirm-salt')
            confirm_url = url_for('confirm_email', token=token, _external=True)
            msg = Message("Confirm Your Email", sender='ghostshadow9111993@gmail.com', recipients=[email])
            msg.body = f"Please confirm your email by clicking the following link: {confirm_url}"
            mail.send(msg)

            flash("A confirmation email has been sent. Please check your inbox.", "info")
            return redirect(url_for('login'))

        except Exception as e:
            logging.error(f"Error during registration: {e}")
            db.session.rollback()
            flash("Registration failed. Please try again.", "danger")

    return render_template('register.html', form=form)



banned_usernames = [
    "admin", "administrator", "root", "superuser", "ghost", "support", "webadmin", 
    "webmaster", "sysadmin", "rootadmin", "systemuser", "backup", "recovery", "maintenance", 
    "null", "useradmin", "readonly", "noreply", "updates", "readonlyadmin", "manager", 
    "operator", "chief", "controller", "apiadmin", "guest", "network", "router", 
    "firewalluser", "master", "vault", "developer", "teamlead", "qaadmin", "headadmin", 
    "datacenter", "serviceadmin", "analytics", "dnsadmin", "port", "loadbalancer", 
    "useraccount", "default", "restrictedadmin", "monitor", "telemetry", "logviewer", 
    "audit", "compliance", "access", "intelligence", "infosec", "infosecurity", 
    "token", "ssladmin", "cipher", "session", "debug", "debugadmin", "test", "testadmin", 
    "auditlog", "vaultuser", "identity", "secops", "block", "privilege", "adminaccount", 
    "healthcheck", "status", "operations", "internaladmin", ".json", ".rss", ".well-known", 
    ".xml", "about", "abuse", "access", "account", "accounts", "activate", "ad", "add", 
    "address", "adm", "ads", "adult", "advertising", "affiliate", "affiliates", "ajax", 
    "analytics", "android", "anon", "anonymous", "api", "app", "apps", "archive", "atom", 
    "auth", "authentication", "autoconfig", "avatar", "bad", "backup", "banner", "banners", 
    "best", "beta", "billing", "bin", "blackberry", "blog", "blogs", "board", "bot", 
    "bots", "broadcasthost", "business", "cache", "calendar", "campaign", "career", 
    "careers", "cart", "cdn", "cgi", "chat", "chef", "client", "clients", "code", 
    "codes", "commercial", "community", "compare", "config", "connect", "contact", 
    "contact-us", "contest", "cookie", "copyright", "corporate", "create", "crossdomain", 
    "crossdomain.xml", "css", "customer", "dash", "dashboard", "data", "database", "db", 
    "delete", "demo", "design", "designer", "dev", "devel", "developer", "developers", 
    "development", "dir", "directory", "dmca", "doc", "docs", "documentation", "domain", 
    "domainadmin", "domainadministrator", "download", "downloads", "ecommerce", "edit", 
    "editor", "email", "embed", "enterprise", "error", "errors", "events", "example", 
    "facebook", "faq", "faqs", "favorite", "favorites", "favourite", "favourites", 
    "features", "feed", "feedback", "feeds", "file", "files", "follow", "font", "fonts", 
    "forum", "forums", "free", "ftp", "gadget", "gadgets", "games", "gift", "git", 
    "good", "google", "group", "groups", "guests", "help", "helpcenter", "home", 
    "homepage", "host", "hosting", "hostmaster", "hostname", "html", "http", "httpd", 
    "https", "image", "images", "imap", "img", "index", "info", "information", 
    "intranet", "invite", "ipad", "iphone", "irc", "is", "isatap", "it", "java", 
    "javascript", "job", "jobs", "js", "json", "knowledgebase", "legal", "license", 
    "list", "lists", "localdomain", "localhost", "log", "login", "logout", "logs", 
    "mail", "mailer-daemon", "mailerdaemon", "manifesto", "marketing", "me", "media", 
    "message", "messages", "messenger", "mob", "mobile", "msg", "mx", "mysql", "name", 
    "named", "net", "network", "new", "newest", "news", "newsletter", "nobody", "noc", 
    "nogroup", "notes", "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "ns7", "ns8", 
    "ns9", "oembed", "old", "online", "operator", "order", "orders", "owner", "page", 
    "pager", "pages", "panel", "password", "perl", "photo", "photos", "php", "pic", 
    "pics", "plan", "plans", "plugin", "plugins", "pop", "pop3", "post", "postfix", 
    "postmaster", "posts", "press", "pricing", "privacy", "profile", "project", 
    "projects", "promo", "public", "python", "random", "recipe", "recipes", "register", 
    "registration", "remove", "request", "reset", "robots", "robots.txt", "rss", "ruby", 
    "sale", "sales", "sample", "samples", "save", "script", "scripts", "search", 
    "secure", "security", "send", "service", "services", "setting", "settings", "setup", 
    "shop", "shopping", "signin", "signout", "signup", "site", "sitemap", "sitemap.xml", 
    "sites", "smtp", "sql", "src", "ssh", "ssl", "ssladmin", "ssladministrator", 
    "sslwebmaster", "stage", "staging", "start", "stat", "static", "stats", "status", 
    "store", "stores", "subdomain", "subscribe", "support", "svn", "sys", "sysadmin", 
    "sysop", "system", "tablet", "tablets", "task", "tasks", "tech", "telnet", "terms", 
    "test", "theme", "themes", "tmp", "tools", "top", "trust", "tutorial", "tutorials", 
    "tv", "twitter", "unsubscribe", "update", "upload", "url", "usage", "usenet", 
    "user", "username", "users", "video", "videos", "visitor", "web", "weblog", 
    "webmail", "website", "websites", "welcome", "wiki", "win", "wpad", "ww", "wws", 
    "www", "www1", "www2", "www3", "www4", "www5", "www6", "www7", "wwws", "wwww", 
    "xml", "xpg", "xxx", "yahoo", "you", "yourdomain", "yourname", "yoursite", 
    "yourusername", "ghostyware", "ghosty", "ghostshadow", "ghostshadowplays"
]


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        # Load the email from the token
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)  # 1-hour expiration
    except Exception:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()

    if user and not user.confirmed:
        user.confirmed = True
        db.session.commit()
        flash('Your email has been confirmed. You can now log in.', 'success')
    else:
        flash('Account already confirmed or not found.', 'info')

    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user.is_online = False  # Set user as offline
            db.session.commit()  # Commit the change

    # Clear the session
    session.pop('user_id', None)
    session.pop('is_admin', None)
    session.pop('last_activity', None)

    flash('Logged out successfully!', 'success')

    # Redirect based on user role (if needed)
    if session.get('is_admin'):
        return redirect(url_for('admin_login'))  # Redirect to admin login if logged in as admin

    return redirect(url_for('home'))  # Otherwise redirect to home

@app.route('/downloads/<path:filename>')
def download_file(filename):
    return send_from_directory('downloads', filename)

@app.route('/projects')
def projects():
    return render_template('projects.html')

@app.route('/tutorials')
def tutorials():
    return render_template('tutorials.html')

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        user_id = session.get('user_id')  # Adjust based on your session management
        message = form.message.data

        # Create a new feedback entry with user information if available
        new_feedback = Feedback(message=message, user_id=user_id)
        db.session.add(new_feedback)
        db.session.commit()

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('feedback'))

    # Fetch feedback entries with user information
    feedback_entries = Feedback.query.join(User).all()  # Ensure to include the user info
    return render_template('feedback.html', form=form, feedback=feedback_entries)

@app.route('/submit-feedback', methods=['GET', 'POST'])
def submit_feedback():
    form = FeedbackForm()

    if form.validate_on_submit():
        if 'user_id' in session:
            user_id = session['user_id']  # Get user_id from session
            username = User.query.get(user_id).username  # Fetch username from user ID
            message = bleach.clean(form.message.data)  # Clean message to prevent XSS

            # Create new feedback entry with user_id
            new_feedback = Feedback(name=username, message=message, date_submitted=datetime.now(), user_id=user_id)
            db.session.add(new_feedback)
            db.session.commit()
            flash('Feedback submitted successfully!', 'success')
            return redirect(url_for('feedback'))
        else:
            flash('You need to be logged in to submit feedback.', 'warning')
            return redirect(url_for('login'))

    feedback = Feedback.query.all()  # Fetch existing feedback to display
    return render_template('feedback.html', form=form, feedback=feedback)



@app.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()

    if form.validate_on_submit():

        name = bleach.clean(form.name.data.strip())
        email = bleach.clean(form.email.data.strip())
        message = bleach.clean(form.message.data.strip())

        new_message = ContactMessage(name=name, email=email, message=message)
        db.session.add(new_message)
        db.session.commit()

        flash('Your message has been sent successfully!', 'success')
        return redirect(url_for('contact'))


    return render_template('contact.html', form=form)


@app.route('/submit-contact', methods=['POST'])
def submit_contact():
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    message = request.form.get('message', '').strip()


    if not name or not email or not message:
        flash("All fields are required.", "danger")
        return redirect(url_for('contact'))


    contact_message = ContactMessage(name=name, email=email, message=message)


    try:
        db.session.add(contact_message)
        db.session.commit()
        flash("Your message has been sent! We'll get back to you soon.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Error saving contact message. Please try again.", "danger")
        print(f"Error: {e}")

    return redirect(url_for('contact'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if authenticate_admin(username, password):
            session['is_admin'] = True  # Set the session for admin
            print("admin logged in, session is_admin set to True")  # Debugging output
            return jsonify({'redirect': url_for('view_messages')})  # Redirect to view messages
        else:
            print("admin login failed")  # Debugging output for failed login
            return jsonify({'message': 'Invalid username or password.'}), 401  # Error response

    # If it's a GET request, just render the login page
    return render_template('admin_login.html')


def authenticate_admin(username, password):
    # Fetch the user from the database
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        print(f"User {username} is_admin status: {user.is_admin}")
        return user.is_admin == 1  # Ensure it returns True if the user is an admin
    return False

@app.route('/view_messages')
@session_timeout
def view_messages():
    if not is_admin():
        flash("You must be an admin to view this page.", "error")
        return redirect(url_for('is_admin_login'))
    
    messages = fetch_messages_from_database()  # Implement this function to retrieve messages
    return render_template('view_messages.html', messages=messages)

STATIC_FOLDER = os.path.join(app.root_path, 'static', 'profile_photos')

from flask import jsonify

@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
def view_user_profile(user_id):
    user = User.query.get(user_id)
    form = FriendRequestForm()  # Instantiate the form

    if user:
        if form.validate_on_submit():
            receiver_id = form.receiver_id.data
            # Add your friend request logic here (e.g., saving to the database)

            # Flash a success message
            flash('Friend request sent successfully!', 'success')

            # If it's an AJAX request, return a JSON response
            if request.is_xhr or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify(success=True, message='Friend request sent successfully!')

            # For normal requests, redirect back to the same profile
            return redirect(url_for('view_user_profile', user_id=user.id))

        return render_template('user_profile.html', user=user, form=form)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('feedback'))



@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    form = ProfileForm()

    # Fetch the user based on session ID
    user = User.query.get(session.get('user_id'))  # Use .get() for safer access
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))

    logging.info(f"Current Bio: {user.bio}")

    if form.validate_on_submit():
        logging.info("Form is valid.")
        
        # Log the incoming data
        logging.info(f"Submitted Bio: {form.bio.data}")

        # Update user's bio
        user.bio = form.bio.data  

        # Handle the uploaded profile photo
        profile_photo = form.profile_photo.data
        if profile_photo:
            filename = secure_filename(profile_photo.filename)
            profile_photos_dir = os.path.join(app.root_path, 'static', 'profile_photos')

            # Create directory if it doesn't exist
            if not os.path.exists(profile_photos_dir):
                os.makedirs(profile_photos_dir)

            # Save the file
            profile_photo.save(os.path.join(profile_photos_dir, filename))
            user.profile_photo = filename  
            logging.info(f"Profile photo updated to: {filename}")

        # Commit changes to the database
        db.session.commit()
        logging.info("Changes committed to the database.")
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    # If validation fails, log the errors
    logging.error(f"Form errors: {form.errors}")

    # Populate the form with the current user's bio for display
    form.bio.data = user.bio if user.bio else ''

    return render_template('profile.html', user=user, form=form)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    logging.info('Accessing profile route.')

    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(id=session['user_id']).first()
    if not user:
        flash('User not found.', 'danger')
        logging.warning(f"User ID {session['user_id']} not found in the database.")
        return redirect(url_for('login'))

    # Create a form for updating the profile
    form = ProfileForm()
    if user.bio:
        form.bio.data = user.bio  # Retain the current bio for the form

    # Retrieve friend requests for the user
    friend_requests = FriendRequest.query.filter_by(receiver_id=user.id, accepted=False).all()

    # Retrieve the user's friends
    friends_list = User.query.join(Friendship, 
                                   (Friendship.user_id == user.id) & (Friendship.friend_id == User.id) | 
                                   (Friendship.friend_id == user.id) & (Friendship.user_id == User.id)) \
                             .all()

    logging.info(f"Retrieved {len(friend_requests)} friend requests and {len(friends_list)} friends for user {user.id}.")

    return render_template('profile.html', user=user, form=form, friends=friends_list, friend_requests=friend_requests)

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    logging.info('Accessing change_email route.')

    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(id=session['user_id']).first()
    logging.info(f'User fetched: {user.email if user else "No user found"}')

    form = ChangeEmailForm()

    if form.validate_on_submit():
        current_password = request.form.get('current_password')  # You'll still need this
        new_email = form.new_email.data

        if not bcrypt.check_password_hash(user.password, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_email'))

        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user:
            flash('This email is already in use. Please choose a different email.', 'danger')
            return redirect(url_for('change_email'))

        try:
            user.email = new_email
            db.session.commit()
            logging.info('Email updated successfully.')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating your email: {str(e)}', 'danger')
            return redirect(url_for('change_email'))

        # Send confirmation email
        msg = Message('Email Change Confirmation',
                      sender='ghostshadow9111993@gmail.com',
                      recipients=[new_email])
        msg.body = 'Your email address has been successfully changed in our system.'
        try:
            mail.send(msg)
            logging.info('Confirmation email sent successfully.')
        except Exception as e:
            flash(f'Failed to send confirmation email: {str(e)}', 'error')

        return redirect(url_for('profile'))

    return render_template('change_email.html', user=user, form=form)


def send_reset_email(user_email, reset_link):
    msg = Message('Password Reset Request',
                  sender='your-email@example.com',
                  recipients=[user_email])
    msg.body = f'Click the following link to reset your password: {reset_link}'
    mail.send(msg)


if __name__ == '__main__':
    app.run(debug=True)
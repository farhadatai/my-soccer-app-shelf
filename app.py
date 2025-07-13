import os
import sqlite3
from datetime import datetime
import functools
import json
import logging
import socket

from flask import Flask, flash, g, redirect, render_template, request, session, url_for, jsonify, abort
from werkzeug.security import check_password_hash, generate_password_hash

# Optional Stripe import
try:
    import stripe
    stripe_available = True
except ImportError:
    stripe = None
    stripe_available = False

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# Stripe config
if stripe_available:
    stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
else:
    STRIPE_PUBLISHABLE_KEY = STRIPE_WEBHOOK_SECRET = None

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE = 'soccer_club.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS player (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            age INTEGER,
            team TEXT,
            parent_id INTEGER,
            coach_id INTEGER,
            progress TEXT,
            FOREIGN KEY (parent_id) REFERENCES user (id),
            FOREIGN KEY (coach_id) REFERENCES user (id)
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_id INTEGER,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (player_id) REFERENCES player (id)
        );
        CREATE TABLE IF NOT EXISTS payment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_id INTEGER,
            amount INTEGER,
            status TEXT DEFAULT 'pending',
            stripe_id TEXT UNIQUE,
            created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (player_id) REFERENCES player (id)
        );
    ''')
    db.commit()

with app.app_context():
    logger.info("Initializing database...")
    init_db()
    logger.info("Database initialized successfully.")

app.teardown_appcontext(close_db)

if stripe_available:
    if not stripe.api_key:
        logger.warning("STRIPE_SECRET_KEY not set. Payments will fail.")
    if not STRIPE_PUBLISHABLE_KEY:
        logger.warning("STRIPE_PUBLISHABLE_KEY not set. Payments will fail.")
    if not STRIPE_WEBHOOK_SECRET:
        logger.warning("STRIPE_WEBHOOK_SECRET not set. Webhooks will fail.")
else:
    logger.warning("Stripe module not available. Payment features are disabled.")

# Helpers
def get_user_by_id(user_id):
    return get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()

def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = get_user_by_id(user_id) if user_id else None

@app.before_request
def before_request():
    load_logged_in_user()

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def role_required(*roles):
    def decorator(view):
        @functools.wraps(view)
        @login_required
        def wrapped_view(**kwargs):
            if g.user['role'] not in roles:
                flash('Access denied.')
                return redirect(url_for('index'))
            return view(**kwargs)
        return wrapped_view
    return decorator

# Routes (completed from previous versions, adapted for new DB structure)
@app.route('/')
def index():
    return render_template('index.html') if os.path.exists('templates/index.html') else "Soccer Club App is running."

@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        db = get_db()
        error = None

        if not full_name or not email or not username or not password or not role:
            error = 'All fields required.'
        elif role not in ['admin', 'coach', 'parent']:
            error = 'Invalid role.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (full_name, email, username, password, role) VALUES (?, ?, ?, ?, ?)",
                    (full_name, email, username, generate_password_hash(password), role),
                )
                db.commit()
                flash('Registered successfully. Please log in.')
                return redirect(url_for('login'))
            except db.IntegrityError:
                error = f"User {username} is already registered."

        flash(error)

    return render_template('register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        if user is None or not check_password_hash(user['password'], password):
            error = 'Incorrect username or password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))

        flash(error)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if g.user['role'] == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif g.user['role'] == 'coach':
        return redirect(url_for('coach_dashboard'))
    elif g.user['role'] == 'parent':
        return redirect(url_for('parent_dashboard'))
    return 'Invalid role.'

@app.route('/admin/dashboard')
@role_required('admin')
def admin_dashboard():
    db = get_db()
    users = db.execute('SELECT * FROM user').fetchall()
    players = db.execute('SELECT * FROM player').fetchall()
    return render_template('admin_dashboard.html', users=users, players=players)

@app.route('/coach/dashboard')
@role_required('coach')
def coach_dashboard():
    db = get_db()
    players = db.execute('SELECT * FROM player WHERE coach_id = ?', (g.user['id'],)).fetchall()
    return render_template('coach_dashboard.html', players=players)

@app.route('/coach/player/add', methods=('GET', 'POST'))
@role_required('coach')
def add_player():
    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        team = request.form['team']
        parent_id = request.form['parent_id']
        db = get_db()
        db.execute(
            'INSERT INTO player (name, age, team, parent_id, coach_id) VALUES (?, ?, ?, ?, ?)',
            (name, age, team, parent_id, g.user['id'])
        )
        db.commit()
        flash('Player added.')
        return redirect(url_for('coach_dashboard'))
    db = get_db()
    parents = db.execute("SELECT * FROM user WHERE role = 'parent'").fetchall()
    return render_template('add_player.html', parents=parents)

@app.route('/coach/player/edit/<int:player_id>', methods=('GET', 'POST'))
@role_required('coach')
def edit_player(player_id):
    db = get_db()
    player = db.execute('SELECT * FROM player WHERE id = ? AND coach_id = ?', (player_id, g.user['id'])).fetchone()
    if not player:
        abort(404)

    if request.method == 'POST':
        if 'mark_attendance' in request.form:
            db.execute('INSERT INTO attendance (player_id) VALUES (?)', (player_id,))
            db.commit()
        progress = request.form.get('progress', player['progress'])

        db.execute(
            'UPDATE player SET progress = ? WHERE id = ?',
            (progress, player_id)
        )
        db.commit()
        flash('Player updated.')
        return redirect(url_for('coach_dashboard'))

    attendance = db.execute('SELECT date FROM attendance WHERE player_id = ?', (player_id,)).fetchall()
    return render_template('edit_player.html', player=player, attendance=attendance)

@app.route('/parent/dashboard')
@role_required('parent')
def parent_dashboard():
    db = get_db()
    players = db.execute('SELECT * FROM player WHERE parent_id = ?', (g.user['id'],)).fetchall()
    payments = db.execute('SELECT * FROM payment WHERE player_id IN (SELECT id FROM player WHERE parent_id = ?)', (g.user['id'],)).fetchall()
    return render_template('parent_dashboard.html', players=players, payments=payments)

@app.route('/parent/pay/<int:player_id>')
@role_required('parent')
def pay(player_id):
    if not stripe_available:
        flash('Payments are disabled.')
        return redirect(url_for('parent_dashboard'))
    db = get_db()
    player = db.execute('SELECT * FROM player WHERE id = ? AND parent_id = ?', (player_id, g.user['id'])).fetchone()
    if not player:
        abort(404)
    return render_template('pay.html', player=player, stripe_key=STRIPE_PUBLISHABLE_KEY)

@app.route('/create-checkout-session/<int:player_id>', methods=['POST'])
@role_required('parent')
def create_checkout_session(player_id):
    if not stripe_available:
        return jsonify(error='Payments disabled'), 403
    db = get_db()
    player = db.execute('SELECT * FROM player WHERE id = ? AND parent_id = ?', (player_id, g.user['id'])).fetchone()
    if not player:
        abort(403)

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {'name': f'Dues for {player["name"]}'},
                    'unit_amount': 20000,  # $200 example
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('payment_success', player_id=player_id, _external=True),
            cancel_url=url_for('payment_cancel', player_id=player_id, _external=True),
        )
        db.execute('INSERT INTO payment (player_id, amount, stripe_id) VALUES (?, ?, ?)', (player_id, 20000, session.id))
        db.commit()
        return jsonify({'id': session.id})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/payment/success/<int:player_id>')
@role_required('parent')
def payment_success(player_id):
    flash('Payment successful!')
    return redirect(url_for('parent_dashboard'))

@app.route('/payment/cancel/<int:player_id>')
@role_required('parent')
def payment_cancel(player_id):
    flash('Payment cancelled.')
    return redirect(url_for('parent_dashboard'))

@app.route('/webhook', methods=['POST'])
def webhook():
    if not stripe_available:
        return 'Payments disabled', 403
    payload = request.data
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400

    if event['type'] == 'checkout.session.completed':
        stripe_session = event['data']['object']
        db = get_db()
        db.execute('UPDATE payment SET status = "paid" WHERE stripe_id = ?', (stripe_session.id,))
        db.commit()

    return jsonify(success=True)

# Run on a free port to avoid conflicts
if __name__ == '__main__':
    try:
        base_port = int(os.environ.get("PORT", 5050))
        port = base_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                sock.bind(('127.0.0.1', port))
                sock.close()
                break
            except OSError:
                port += 1
        logger.info(f"Starting Flask app on http://127.0.0.1:{port}")
        app.run(debug=False, host='127.0.0.1', port=port)
    except Exception as e:
        logger.error(f"Error starting app: {e}")
        print("Please check your environment or try a different port.")
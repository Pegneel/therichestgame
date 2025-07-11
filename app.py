import os
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
import stripe

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# OAuth - login con Google
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'}
)

# Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
stripe_pub_key = os.getenv("STRIPE_PUBLIC_KEY")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    name = db.Column(db.String(120))
    total_donated = db.Column(db.Float, default=0.0)

class FakeUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    total_donated = db.Column(db.Float, default=0.0)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    redirect_uri = url_for('authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/login/authorized')
def authorized():
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    session['user'] = user_info
    user = User.query.filter_by(email=user_info['email']).first()
    if not user:
        user = User(email=user_info['email'], name=user_info['name'])
        db.session.add(user)
        db.session.commit()
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    real_users = User.query.all()
    fake_users = FakeUser.query.all()
    users = sorted(real_users + fake_users, key=lambda u: u.total_donated, reverse=True)
    return render_template('dashboard.html', users=users, current_user=session['user'])

@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    if 'user' not in session:
        return redirect('/')
    amount = float(request.form.get('amount', 0))
    if amount < 0.5:
        return "Amount too low", 400
    amount_cents = int(amount * 100)
    session['donation_amount'] = amount
    success_url = url_for('success', _external=True)
    cancel_url = url_for('dashboard', _external=True)
    checkout_session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'eur',
                'product_data': {'name': 'The Richest Donation'},
                'unit_amount': amount_cents,
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=success_url + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=cancel_url,
        billing_address_collection='auto',
        customer_email=session['user']['email'],
        metadata={'user_email': session['user']['email']}
    )
    return redirect(checkout_session.url, code=303)

@app.route('/donate', methods=['POST'])
def donate():
    if 'user' not in session:
        return redirect('/')
    amount = float(request.form.get('amount', 0))
    user = User.query.filter_by(email=session['user']['email']).first()
    if user:
        user.total_donated += float(amount)
        db.session.commit()
    return redirect('/dashboard')

@app.route('/reset', methods=['POST'])
def reset():
    if 'user' in session and session['user']['email'] == 'andrewpegoraro94@gmail.com':
        db.session.query(User).delete()
        db.session.query(FakeUser).delete()
        db.session.commit()
    return redirect('/dashboard')

@app.route('/fake_donation', methods=['POST'])
def fake_donation():
    if 'user' in session and session['user']['email'] == 'andrewpegoraro94@gmail.com':
        name = request.form.get('name')
        amount = float(request.form.get('amount'))
        user = FakeUser.query.filter_by(name=name).first()
        if not user:
            user = FakeUser(name=name, total_donated=0.0)
            db.session.add(user)
        if user.total_donated is None:
            user.total_donated = 0.0
        user.total_donated += amount
        db.session.commit()
    return redirect('/dashboard')

@app.route('/success')
def success():
    session_id = request.args.get('session_id')
    if not session_id:
        return redirect('/login')
    stripe_session = stripe.checkout.Session.retrieve(session_id)
    user_email = stripe_session.metadata.get('user_email')
    amount = stripe_session.amount_total / 100.0
    user = User.query.filter_by(email=user_email).first()
    if user:
        if session.get('last_processed') != session_id:
            user.total_donated += float(amount)
            db.session.commit()
            session['last_processed'] = session_id
        session['user'] = {'email': user.email, 'name': user.name}
    return redirect('/dashboard')

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

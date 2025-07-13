from flask import Flask, render_template, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask import jsonify
import os
import stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
from dotenv import load_dotenv
load_dotenv()


load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or "this_should_be_changed"

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
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
stripe_pub_key = os.getenv("STRIPE_PUBLIC_KEY")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(100))
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
    redirect_uri = url_for('auth', _external=True)  # usa 'auth' qui
    return google.authorize_redirect(redirect_uri)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/login/auth')
def auth():
    token = google.authorize_access_token()
    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    user_info = resp.json()
    session['user'] = user_info

    user = User.query.filter_by(email=user_info['email']).first()

    if not user:
        user = User(email=user_info['email'], name=user_info['name'])
        db.session.add(user)
        db.session.commit()

    if not user.username:
        return redirect('/set_username')

    return redirect('/dashboard')




@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    real_users = User.query.all()
    fake_users = FakeUser.query.all()
    users = sorted(real_users + fake_users, key=lambda u: u.total_donated, reverse=True)
    logged_in_user = User.query.filter_by(email=session['user']['email']).first()
    return render_template('dashboard.html', users=users, current_user=logged_in_user)


@app.route('/set_username', methods=['GET', 'POST'])
def set_username():
    if 'user' not in session:
        return redirect('/')

    current_email = session['user']['email']
    user = User.query.filter_by(email=current_email).first()

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()

        # Controlli
        if len(new_username) < 1 or len(new_username) > 20:
            return render_template('choose_username.html', error="Username must be 1–20 characters.")

        if User.query.filter(User.username == new_username, User.email != current_email).first():
            return render_template('choose_username.html', error="Username already taken.")

        user.username = new_username
        db.session.commit()
        return redirect('/dashboard')

    return render_template('choose_username.html', error=None)


@app.route('/create-checkout-session', methods=['POST'])
def create_checkout_session():
    if 'user' not in session:
        return redirect('/')
    amount = float(request.form.get('amount', 0))
    if amount < 0.5:
        return "Amount too low", 400
    amount_cents = int(amount * 100)
    session['donation_amount'] = amount

    # URL assoluti per l'ambiente di produzione
    success_url = "https://therichestgame.com/success"
    cancel_url = "https://therichestgame.com/dashboard"

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
    if amount <= 0:
        return redirect('/dashboard')

    # Crea sessione Stripe
    session_stripe = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'eur',
                'product_data': {
                    'name': 'Giocata su The Richest',
                },
                'unit_amount': int(amount * 100),  # converti euro in centesimi
            },
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('success', _external=True),
        cancel_url=url_for('dashboard', _external=True),
        metadata={
            'email': session['user']['email'],
            'amount': amount
        }
    )

    return redirect(session_stripe.url, code=303)


@app.route('/reset', methods=['POST'])
def reset():
    if 'user' in session and session['user']['email'] == 'andrewpegoraro94@gmail.com':
        db.session.query(User).delete()
        db.session.query(FakeUser).delete()
        db.session.commit()
    return redirect('/dashboard')

@app.route('/fake_donation', methods=['POST'])
def fake_donation():
    if 'user' not in session or session['user']['email'] != 'andrewpegoraro94@gmail.com':
        return redirect('/')

    name = request.form.get('name')
    amount = float(request.form.get('amount'))

    if not name or amount <= 0:
        return "Invalid data", 400

    # Cerca un utente esistente con quel nome
    user = User.query.filter_by(name=name).first()
    if not user:
        fake_email = f"{name.replace(' ', '').lower()}@fake.com"
        user = User(name=name, email=fake_email, total_donated=0.0)
        db.session.add(user)

    user.total_donated += amount
    db.session.commit()
    return redirect('/dashboard')


@app.route('/disclaimer')
def disclaimer():
    return render_template('legal/disclaimer.html')

@app.route('/terms')
def terms():
    return render_template('legal/terms.html')

@app.route('/privacy')
def privacy():
    return render_template('legal/privacy.html')

@app.route('/api/leaderboard')
def api_leaderboard():
    users = User.query.order_by(User.total_donated.desc()).limit(50).all()
    data = [{'name': u.username or u.name, 'amount': u.total_donated} for u in users]
    return jsonify(data)

@app.route('/success')
def success():
    session_id = request.args.get('session_id')
    print("✅ Success route reached, session_id:", session_id)

    if not session_id:
        return "Missing session ID", 400

    try:
        session_data = stripe.checkout.Session.retrieve(session_id)
        customer_email = session_data['customer_email']
        amount_total = session_data['amount_total'] / 100  # da centesimi a euro

        print(f"✅ Payment by {customer_email}: €{amount_total}")

        user = User.query.filter_by(email=customer_email).first()
        if user:
            user.total_donated += amount_total
            db.session.commit()
            print(f"✅ Updated {user.name}'s total to €{user.total_donated}")
        else:
            print("❌ User not found in database")

    except Exception as e:
        print("❌ Error in success route:", str(e))
        return "Error processing payment", 500

    return redirect('/dashboard')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)


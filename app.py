from flask import Flask, render_template, flash, redirect, url_for, session, request, logging, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from wtforms.fields import DateField,DateTimeField, DateTimeLocalField
from wtforms.validators import DataRequired, Length, EqualTo
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY']='secret123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://dbadmin:Crastlebee0@postgresdb-crastlebee.postgres.database.azure.com:5432/crastlebee'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime, nullable=False)
    is_processed = db.Column(db.Boolean, nullable=False)
    is_valid = db.Column(db.Boolean, nullable=False)
    user = db.Column(db.String(130), nullable=False)

# Automatically create the database tables if they don't exist
with app.app_context():
    db.create_all()

# Register Form Classes
class RegisterForm(FlaskForm):
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

class EventForm(FlaskForm):
    title = StringField('Title', [Length(min=1, max=200)])
    type = SelectField('Type', choices=["Heures Supplémentaires", "Congés payés", "Arrêt maladie et congés payés annuels", "Jours fériés et ponts", "Réduction du temps de travail (RTT)", "Congés sans solde", "Congé maternité", "Congé de paternité et d'accueil de l'enfant", "Congé en cas d'hospitalisation immédiate de l'enfant après sa naissance", "Congé d'adoption", "Congé de 3 jours pour naissance ou adoption", "Congé parental à temps plein", "Congé pour enfant malade", "Congé de présence parentale", "Congé de proche aidant", "Congé de solidarité familiale", "Allocation journalière d'accompagnement d'une personne en fin de vie", "Survenue du handicap d'un enfant", "Don de jours de repos pour enfant gravement malade", "Don de jours de repos à un salarié dont l'enfant est décédé", "Création ou reprise d'entreprise", "Exercice d'un mandat politique local", "Mariage ou Pacs", "Mariage de son enfant", "Décès d'un membre de sa famille", "Congé sabbatique"])
    start_datetime = DateTimeLocalField('Start Date and Time',
                                        format='%Y-%m-%dT%H:%M',
                                        validators=[DataRequired()])
    end_datetime = DateTimeLocalField('End Date and Time',
                                      format='%Y-%m-%dT%H:%M',
                                      validators=[DataRequired()])

    def validate(self, **kwargs):
        # Standard validation
        rv = FlaskForm.validate(self)
        # Ensure start date/time is before end date/time
        if rv:
            if self.start_datetime.data >= self.end_datetime.data:
                self.start_datetime.errors.append("Start date and time must be before end date and time.")
                return False
            return True

        return False

class UserSelectionForm(FlaskForm):
    user_id = SelectField('Select User', coerce=int, validators=[DataRequired()])

@app.route('/')
def index():
    return render_template('home.html')

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        if email == "ahmed.chreif@castlebee.fr" or email == "nicolas.desouza@castlefrog.fr":
            is_admin = True
        else:
            is_admin = False

        new_user = User(email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user:
            password = user.password
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['email'] = email
                if user.is_admin == True:
                    session['is_admin'] = True
                    flash('You are now logged in as admin', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('You are now logged in', 'success')
                    return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session and 'is_admin' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, admin access required', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    form = UserSelectionForm()
    all_users = User.query.all()
    user_choices = [(user.id, user.email) for user in all_users]

    form.user_id.choices = user_choices
    selected_user_id = request.args.get('user_id', type=int)

    if selected_user_id:
        selected_user_email = User.query.filter_by(id=selected_user_id).first()
        calendar = Event.query.filter_by(user=selected_user_email.email, is_valid=True).all()
    else:
        calendar = Event.query.filter_by(user=session['email'], is_valid=True).all()

    return render_template('admin_dashboard.html', calendar=calendar, form=form)

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    user = User.query.filter_by(email=session['email']).first()

    if user:
        calendar = Event.query.filter_by(user=session['email'], is_valid=True).all()
        list = Event.query.filter_by(user=session['email']).all()

        if calendar:
            return render_template('dashboard.html', calendar=calendar, list=list)
        else:
            msg = 'No Events Created'
            return render_template('dashboard.html', msg=msg)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

#Admin
@app.route('/admin')
@admin_required
def admin():
    user = User.query.filter_by(email=session['email']).first()

    if user:
        calendar = Event.query.all()

        if calendar:
            return render_template('admin.html', calendar=calendar)
        else:
            msg = 'No Events or Supps to Process'
            return render_template('admin.html', msg=msg)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('login'))


#Add Conges
@app.route('/add_events', methods=['GET', 'POST'])
@is_logged_in
def add_events():
    form = EventForm()
    if form.validate_on_submit():
        title = form.title.data
        type = form.type.data
        start = form.start_datetime.data
        end = form.end_datetime.data
        is_processed = False
        is_valid = False

        new_event = Event(title=title, type=type, start=start, end=end, is_processed=is_processed, is_valid=is_valid, user=session['email'])
        db.session.add(new_event)
        db.session.commit()

        flash('Event Created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_events.html', form=form)

@app.route('/accept_event/<int:event_id>', methods=['POST'])
@admin_required  # Ensure only admin can access this route
def accept_event(event_id):
    event = Event.query.get(event_id)
    if event and not event.is_processed:
        event.is_valid = True
        event.is_processed = True
        db.session.commit()
        flash('Event accepted', 'success')
    else:
        flash('Invalid event or already processed', 'danger')
    return redirect(url_for('admin'))

@app.route('/reject_event/<int:event_id>', methods=['POST'])
@admin_required  # Ensure only admin can access this route
def reject_event(event_id):
    event = Event.query.get(event_id)
    if event and not event.is_processed:
        event.is_valid = False
        event.is_processed = True
        db.session.commit()
        flash('Event rejected', 'success')
    else:
        flash('Invalid event or already processed', 'danger')
    return redirect(url_for('admin'))

@app.route('/remove_event/<int:event_id>', methods=['POST'])
@is_logged_in
def remove_event(event_id):
    event = Event.query.get(event_id)
    if event and not event.is_processed:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted', 'success')
    else:
        flash('Invalid event or already processed', 'danger')
    return redirect(url_for('dashboard'))


# Get calendar events
@app.route('/get_calendar_events', methods=['GET'])
def get_calendar_events():
    calendar = Event.query.filter_by(user=session['email']).all()

    events = []
    if calendar:
        for event in calendar:
            event_data = {
                'start': event.start.strftime('%Y-%m-%dT%H:%M:%S'),
                'end': event.end.strftime('%Y-%m-%dT%H:%M:%S'),
                'type': event.type,
                'title': event.title,
                'id': event.id,
                'backgroundColor': '#f56954'
            }
            events.append(event_data)

    return jsonify(events)

# Insert event
@app.route('/insert_event', methods=['POST'])
def insert_event():
    if request.method == 'POST':
        title = request.form['title']
        start = request.form['start']
        end = request.form['end']

        new_event = Event(title=title, start=start, end=end, user=session['email'])
        db.session.add(new_event)
        db.session.commit()

        return jsonify({'status': 'success'})

# Update event
@app.route('/update_event', methods=['POST'])
def update_event():
    if request.method == 'POST':
        title = request.form['title']
        start = request.form['start']
        end = request.form['end']
        event_id = request.form['id']

        event = Event.query.get(event_id)
        if event:
            event.title = title
            event.start = start
            event.end = end
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})

# Delete event
@app.route('/delete_event', methods=['POST'])
def delete_event():
    if request.method == 'POST':
        event_id = request.form['id']

        event = Event.query.get(event_id)
        if event:
            db.session.delete(event)
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(host='0.0.0.0', debug=True)

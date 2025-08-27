import base64
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, abort, send_file, current_app, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_uploads import UploadSet, configure_uploads, IMAGES, DOCUMENTS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps
from config import Config
from xhtml2pdf import pisa
from io import BytesIO
import logging
from flask_mail import Mail, Message as MailMessage
from sqlalchemy.exc import SQLAlchemyError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

# ✅ Database Config
# Use DATABASE_URL from Render if available, else fallback to SQLite (for local dev)
db_url = os.environ.get("DATABASE_URL")
if not db_url:
    raise RuntimeError("❌ DATABASE_URL is not set. Please configure your Neon Postgres URL in .env")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url

print("🔗 Using database:", app.config["SQLALCHEMY_DATABASE_URI"])


app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Mail config
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "mpc0679@gmail.com"
app.config["MAIL_PASSWORD"] = "cgjg xxug irfw gjyp"
app.config["MAIL_DEFAULT_SENDER"] = "mpc0679@gmail.com"

# Ensure cookies work correctly on mobile/HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot access cookies
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Prevent CSRF issues
app.config["ADMIN_EMAIL"] = "info@mpc.com"
app.config["ADMIN_PASSWORD"] = "0220Mpc#"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "info@mpc.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "0220Mpc#")


# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Custom decorator for admin required
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def create_admin():
    with app.app_context():
        if not User.query.filter_by(email="info@mpc.com").first():
            admin = User(
                email="info@mpc.com",
                password=generate_password_hash("0220Mpc#"),
                first_name="AGICO STAFF",     # ✅ required
                last_name="Admin",       # ✅ required
                phone="+25765777555",      # ✅ required if not null
                role="admin",
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()


# Context processors
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# Configure file uploads
images = UploadSet('images', IMAGES)
docs = UploadSet('docs', DOCUMENTS)
configure_uploads(app, (images, docs))

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120),  nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default='client')  # 'client' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)

    # Relationships
    auto_insurance_requests = db.relationship('AutoInsuranceRequest', back_populates='user', lazy=True)
    travel_insurance_requests = db.relationship('TravelInsuranceRequest', back_populates='user', lazy=True)
    comesa_insurance_requests = db.relationship('ComesaInsuranceRequest', back_populates='user', lazy=True)
    accident_declarations = db.relationship('AccidentDeclaration', back_populates='user', lazy=True)

    messages_sent = db.relationship(
        'Message',
        foreign_keys='Message.user_id',
        backref='sender',
        lazy=True
    )
    messages_received = db.relationship(
        'Message',
        foreign_keys='Message.admin_id',
        backref='receiver',
        lazy=True
    )

    def __repr__(self):
        return f'<User {self.email}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # sender id
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # receiver id (admin)
    is_admin = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.id} - User: {self.user_id}, Admin: {self.admin_id}>'

# Email sending functions - CORRECTED VERSION
def send_confirmation_email(to, subject_suffix):
    try:
        msg = MailMessage(
            subject=f'Agico Client Care - {subject_suffix} Received',
            recipients=[to],
            body=f'''
Thank you for your {subject_suffix.lower()}.

We have received your submission and will process it shortly.
You can check the status in your Agico Client Care dashboard.

Best regards,
Agico Client Care Team
'''
        )
        mail.send(msg)
        logger.info(f"Confirmation email sent to {to}")
        return True
    except Exception as e:
        logger.error(f"Failed to send confirmation email: {str(e)}")
        return False

def send_status_email(recipient, request_type, status):
    try:
        msg = MailMessage(
            subject=f'Your {request_type} has been {status}',
            recipients=[recipient],
            body=f'''
Your {request_type} has been {status}.

You can view the details in your Agico Client Care dashboard.

Best regards,
Agico Client Care Team
'''
        )
        mail.send(msg)
        logger.info(f"Status email sent to {recipient} about {request_type} status: {status}")
        return True
    except Exception as e:
        logger.error(f"Failed to send status email: {str(e)}")
        return False


class AutoInsuranceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='auto_insurance_requests')
    carte_rose = db.Column(db.String(255))
    ancient_card = db.Column(db.String(255))
    phone = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    

class TravelInsuranceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='travel_insurance_requests')
    passport = db.Column(db.String(255))
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    destination = db.Column(db.String(100), nullable=False)
    days = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')
    departure_date = db.Column(db.Date, nullable=True)
    return_date = db.Column(db.Date, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ComesaInsuranceRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='comesa_insurance_requests')
    carte_rose = db.Column(db.String(255))
    ancient_card = db.Column(db.String(255))
    phone = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AccidentDeclaration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='accident_declarations')
    name = db.Column(db.String(100), nullable=False)
    car_type = db.Column(db.String(100), nullable=False)
    plate_license = db.Column(db.String(50), nullable=False)
    opg_measure = db.Column(db.Boolean, nullable=False)
    car_working = db.Column(db.Boolean, nullable=False)
    opj_name = db.Column(db.String(100))
    opj_phone = db.Column(db.String(20))
    accident_datetime = db.Column(db.DateTime)
    injured_people = db.Column(db.Boolean, nullable=False)
    car_damage = db.Column(db.String(255))
    collided_with_name = db.Column(db.String(100))
    collided_with_plate = db.Column(db.String(50))
    collided_damage = db.Column(db.String(255))
    injured_details = db.Column(db.Text)
    witness = db.Column(db.Text)
    accident_image1 = db.Column(db.String(255))
    accident_image2 = db.Column(db.String(255))
    accident_image3 = db.Column(db.String(255))
    carte_rose_image = db.Column(db.String(255))
    insurance_card_image = db.Column(db.String(255))
    driving_license_image = db.Column(db.String(255))
    summary = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# Create database tables
with app.app_context():
    try:
        # Check if migrations directory exists, if not create it
        migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
        if not os.path.exists(migrations_dir):
            print("Migrations directory doesn't exist. Creating it...")
            os.makedirs(migrations_dir)
            
        # Initialize database
        db.create_all()
        print("✅ Database tables created successfully")
        
    except Exception as e:
        print(f"⚠️ Database initialization failed: {e}")
        # If there's an error, try to create the tables directly
        try:
            db.create_all()
            print("✅ Database tables created using create_all()")
        except Exception as e2:
            print(f"❌ Database creation completely failed: {e2}")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', 
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        # Prevent registration with admin email - UPDATED
        if email.data == 'info@agico.com':  # Use the specific admin email
            raise ValidationError('This email is reserved for admin use.')
        
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class AutoInsuranceForm(FlaskForm):
    carte_rose = StringField('Carte Rose Image', validators=[DataRequired()])
    ancient_card = StringField('Ancient Card Image', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Submit Request')

class TravelInsuranceForm(FlaskForm):
    passport = StringField('Passport Image', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    destination = StringField('Destination', validators=[DataRequired()])
    days = IntegerField('Days to Spend', validators=[DataRequired()])
    submit = SubmitField('Submit Request')

class ComesaInsuranceForm(FlaskForm):
    carte_rose = StringField('Carte Rose Image', validators=[DataRequired()])
    ancient_card = StringField('Ancient Card Image', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    submit = SubmitField('Submit Request')

class AccidentDeclarationForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    car_type = StringField('Your Car Type', validators=[DataRequired()])
    plate_license = StringField('Plate License', validators=[DataRequired()])
    opg_measure = BooleanField('Did OPG measure?')
    car_working = BooleanField('Is the car working now?')
    opj_name = StringField('Name of OPJ')
    opj_phone = StringField('OPJ Phone Number')
    accident_datetime = StringField('Date and Time of Accident', validators=[DataRequired()])
    injured_people = BooleanField('Were there any injured people?')
    car_damage = StringField('What happened to your car?')
    collided_with_name = StringField('Name of person you collided with')
    collided_with_plate = StringField('Their car plate license')
    collided_damage = StringField('What got damaged on their car')
    injured_details = StringField('Names and addresses of injured ones')
    witness = StringField('Witness/Icabona')
    accident_image1 = StringField('First Accident Image', validators=[DataRequired()])
    accident_image2 = StringField('Second Accident Image')
    accident_image3 = StringField('Third Accident Image')
    carte_rose_image = StringField('Carte Rose Image', validators=[DataRequired()])
    insurance_card_image = StringField('Insurance Card Image', validators=[DataRequired()])
    driving_license_image = StringField('Driving License Image', validators=[DataRequired()])
    summary = TextAreaField('Accident Summary', validators=[DataRequired()])
    submit = SubmitField('Finish Declaration')

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # REMOVED: Check if user already exists
            # existing_user = User.query.filter_by(email=form.email.data).first()
            # if existing_user:
            #     flash('Email already registered. Please use a different email.', 'danger')
            #     return render_template('auth/register.html', title='Register', form=form)
            
            hashed_password = generate_password_hash(form.password.data)
            user = User(
                email=form.email.data,
                password=hashed_password,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                phone=form.phone.data
            )
            
            if form.email.data == app.config['ADMIN_EMAIL']:
                user.role = 'admin'
            
            db.session.add(user)
            db.session.commit()
            
            # Check if request is from mobile
            user_agent = request.headers.get('User-Agent', '').lower()
            is_mobile = any(device in user_agent for device in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])
            
            flash('Your account has been created! You can now log in.', 'success')
            
            # For mobile devices, provide a more prominent success message
            if is_mobile:
                return render_template('auth/register_success.html', title='Registration Successful')
                
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            app.logger.error(f'Registration error: {str(e)}')
    
    return render_template('auth/register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        users = User.query.filter_by(email=form.email.data).all()
        
        # Debug logging
        print(f"Login attempt: {form.email.data}")
        print(f"Users found: {len(users)}")
        
        if len(users) == 0:
            flash('No account found with this email.', 'danger')
        elif len(users) == 1:
            # Single user - proceed normally
            user = users[0]
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                
                if user.role == 'admin':
                    return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
                else:
                    return redirect(next_page) if next_page else redirect(url_for('dashboard'))
            else:
                flash('Invalid password.', 'danger')
        else:
            # Multiple users - show selection page
            # Verify at least one user has matching password
            valid_user_exists = any(check_password_hash(user.password, form.password.data) for user in users)
            
            if valid_user_exists:
                return render_template('auth/select_account.html', 
                                     users=users, 
                                     email=form.email.data,
                                     password=form.password.data)
            else:
                flash('Invalid password for all accounts with this email.', 'danger')
    
    return render_template('auth/login.html', title='Login', form=form)

@app.route('/select-account', methods=['POST'])
def select_account():
    user_id = request.form.get('user_id')
    password = request.form.get('password')
    remember = request.form.get('remember') == 'true'
    
    user = User.query.get(user_id)
    if user and check_password_hash(user.password, password):
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        
        if user.role == 'admin':
            return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))
        else:
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
    else:
        flash('Invalid selection or password mismatch.', 'danger')
        return redirect(url_for('login'))
    
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



# Client routes
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    
    auto_requests = AutoInsuranceRequest.query.filter_by(user_id=current_user.id).all()
    travel_requests = TravelInsuranceRequest.query.filter_by(user_id=current_user.id).all()
    comesa_requests = ComesaInsuranceRequest.query.filter_by(user_id=current_user.id).all()
    accident_declarations = AccidentDeclaration.query.filter_by(user_id=current_user.id).all()
    
    return render_template('client/dashboard.html', 
                         auto_requests=auto_requests,
                         travel_requests=travel_requests,
                         comesa_requests=comesa_requests,
                         accident_declarations=accident_declarations)

@app.route('/request/auto', methods=['GET', 'POST'])
@login_required
def request_auto():
    form = AutoInsuranceForm()
    
    if form.validate_on_submit():
        carte_rose_filename = None
        ancient_card_filename = None
        
        if 'carte_rose' in request.files:
            carte_rose_file = request.files['carte_rose']
            if carte_rose_file.filename != '':
                carte_rose_filename = images.save(carte_rose_file)
        
        if 'ancient_card' in request.files:
            ancient_card_file = request.files['ancient_card']
            if ancient_card_file.filename != '':
                ancient_card_filename = images.save(ancient_card_file)
        
        request_auto = AutoInsuranceRequest(
            user_id=current_user.id,
            carte_rose=carte_rose_filename,
            ancient_card=ancient_card_filename,
            phone=form.phone.data
        )
        
        db.session.add(request_auto)
        db.session.commit()
        
        # Send confirmation email
        send_confirmation_email(current_user.email, "Auto Insurance Request")
        
        flash('Your auto insurance request has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('client/request_auto.html', form=form)

@app.route('/request/travel', methods=['GET', 'POST'])
@login_required
def request_travel():
    form = TravelInsuranceForm()
    
    if form.validate_on_submit():
        passport_filename = None
        if 'passport' in request.files:
            passport_file = request.files['passport']
            if passport_file.filename != '':
                passport_filename = images.save(passport_file)
        
        request_travel = TravelInsuranceRequest(
            user_id=current_user.id,
            passport=passport_filename,
            email=form.email.data,
            phone=form.phone.data,
            destination=form.destination.data,
            days=form.days.data
        )
        
        db.session.add(request_travel)
        db.session.commit()
        
        # Send confirmation email
        send_confirmation_email(current_user.email, "Travel Insurance Request")
        
        flash('Your travel insurance request has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('client/request_travel.html', form=form)

@app.route('/request/comesa', methods=['GET', 'POST'])
@login_required
def request_comesa():
    form = ComesaInsuranceForm()
    
    if form.validate_on_submit():
        carte_rose_filename = None
        ancient_card_filename = None
        
        if 'carte_rose' in request.files:
            carte_rose_file = request.files['carte_rose']
            if carte_rose_file.filename != '':
                carte_rose_filename = images.save(carte_rose_file)
        
        if 'ancient_card' in request.files:
            ancient_card_file = request.files['ancient_card']
            if ancient_card_file.filename != '':
                ancient_card_filename = images.save(ancient_card_file)
        
        request_comesa = ComesaInsuranceRequest(
            user_id=current_user.id,
            carte_rose=carte_rose_filename,
            ancient_card=ancient_card_filename,
            phone=form.phone.data
        )
        
        db.session.add(request_comesa)
        db.session.commit()
        
        # Send confirmation email
        send_confirmation_email(current_user.email, "COMESA Insurance Request")
        
        flash('Your COMESA insurance request has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('client/request_comesa.html', form=form)

@app.route('/declare-accident', methods=['GET', 'POST'])
@login_required
def declare_accident():
    form = AccidentDeclarationForm()
    
    if form.validate_on_submit():
        filenames = {}
        for field in ['accident_image1', 'accident_image2', 'accident_image3', 
                     'carte_rose_image', 'insurance_card_image', 'driving_license_image']:
            if field in request.files:
                file = request.files[field]
                if file.filename != '':
                    filenames[field] = images.save(file)
        
        try:
            accident_datetime = datetime.strptime(form.accident_datetime.data, '%Y-%m-%dT%H:%M')
        except:
            accident_datetime = datetime.utcnow()
        
        declaration = AccidentDeclaration(
            user_id=current_user.id,
            name=form.name.data,
            car_type=form.car_type.data,
            plate_license=form.plate_license.data,
            opg_measure=form.opg_measure.data,
            car_working=form.car_working.data,
            opj_name=form.opj_name.data,
            opj_phone=form.opj_phone.data,
            accident_datetime=accident_datetime,
            injured_people=form.injured_people.data,
            car_damage=form.car_damage.data,
            collided_with_name=form.collided_with_name.data,
            collided_with_plate=form.collided_with_plate.data,
            collided_damage=form.collided_damage.data,
            injured_details=form.injured_details.data,
            witness=form.witness.data,
            accident_image1=filenames.get('accident_image1'),
            accident_image2=filenames.get('accident_image2'),
            accident_image3=filenames.get('accident_image3'),
            carte_rose_image=filenames.get('carte_rose_image'),
            insurance_card_image=filenames.get('insurance_card_image'),
            driving_license_image=filenames.get('driving_license_image'),
            summary=form.summary.data
        )
        
        db.session.add(declaration)
        db.session.commit()
        
        # Send confirmation email
        send_confirmation_email(current_user.email, "Accident Declaration")
        
        flash('Your accident declaration has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('client/declare_accident.html', form=form)

@app.route('/branches')
@login_required
def branches():
    branches_list = [
        {'name': 'AGICO SIEGE', 'phone': '+25762555777'},
        {'name': 'AGENCE KAMENGE', 'phone': '+25779721192'},
        {'name': 'AGENCE KINAMA II', 'phone': '+25769100024'},
        {'name': 'AGENCE CARAMA II', 'phone': '+25765183560'},
        {'name': 'AGENCE NGOZI', 'phone': '+25779726410'},
        {'name': 'AGENCE KIRUNDO', 'phone': '+25779884523'},
        {'name': 'AGENCE MUYINGA/KOBERO I', 'phone': '+25769776088'},
        {'name': 'AGENCE RUYIGI', 'phone': '+25769487436'},
        {'name': 'AGENCE KAYANZA V', 'phone': '+25769305007'},
        {'name': 'AGENCE KAYANZA II', 'phone': '+25761685573'},
        {'name': 'AGENCE RUBIRIZI', 'phone': '+25769406473'},
        {'name': 'AGENCE GITEGA', 'phone': '+25762274776'},
        {'name': 'AGENCE RUTANA', 'phone': '+25767539556'},
        {'name': 'AGENCE RUTANA/GIHARO', 'phone': '+25768147654'},
        {'name': 'AGENCE RUMONGE', 'phone': '+25761186688'},
        {'name': 'CANKUZO', 'phone': '+25762183760'},
        {'name': 'AGENCE MATANA', 'phone': '+25767269307'},
        {'name': 'AGENCE RUGOMBO', 'phone': '+25761508088 '},
        {'name': 'AGENCE CIBITOKE E-HOME', 'phone': '+25767676373'},
        {'name': 'AGENCE BUKEYE', 'phone': '+25771988517'},
        {'name': 'AGENCE NGOZI I', 'phone': '+25768596164 '},
        {'name': 'AGENCE MASANGANZIRA', 'phone': '+25761140429'},
        {'name': 'AGENCE MAKAMBA', 'phone': '+25762387745'},
        {'name': 'AGENCE NYANZA LAC', 'phone': '+25762692223'},
        {'name': 'AGENCE MUSENYI', 'phone': '+25779918552'},
        {'name': 'AGENCE BUBANZA', 'phone': '+25779999811'},
        {'name': 'AGENCE KINAMA A', 'phone': '+25779999811'},
        {'name': 'GUICHER MARCHER KINAMA', 'phone': '+25779918735'},
        {'name': 'GUICHET MAIRIE', 'phone': '+25779746410'},
        {'name': 'GUICHET COTEBU E-HOME', 'phone': '+25768026070'}
    ]
    return render_template('client/branches.html', branches=branches_list)

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'send':
            content = request.form.get('message')
            new_message = Message(
                content=content,
                user_id=current_user.id,
                admin_id=None,
                is_admin=False
            )
            db.session.add(new_message)
        elif action == 'delete':
            message_id = request.form.get('message_id')
            message = Message.query.get(message_id)
            if message and message.user_id == current_user.id:
                db.session.delete(message)
        
        db.session.commit()
    
    messages = Message.query.filter(
        (Message.user_id == current_user.id) |
        (Message.admin_id == current_user.id)
    ).order_by(Message.created_at).all()
    
    # Mark admin messages as read
    Message.query.filter_by(user_id=current_user.id, is_read=False, is_admin=True).update({'is_read': True})
    db.session.commit()
    
    return render_template('client/chat.html', messages=messages)

@app.route('/admin/chat', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_chat():
    clients = User.query.filter_by(role='client').all()
    user_id = request.args.get('user_id')
    
    selected_user = None
    messages = []
    
    if user_id:
        selected_user = User.query.get(user_id)
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'send':
                content = request.form.get('message')
                new_message = Message(
                    content=content,
                    user_id=user_id,
                    admin_id=current_user.id,
                    is_admin=True
                )
                db.session.add(new_message)
            elif action == 'delete':
                message_id = request.form.get('message_id')
                message = Message.query.get(message_id)
                if message and (message.admin_id == current_user.id or message.user_id == user_id):
                    db.session.delete(message)
            
            db.session.commit()
        
        messages = Message.query.filter(
            (Message.user_id == user_id) |
            ((Message.admin_id == current_user.id) & (Message.user_id == user_id))
        ).order_by(Message.created_at).all()
        
        # Mark client messages as read
        Message.query.filter_by(user_id=user_id, admin_id=current_user.id, is_read=False, is_admin=False).update({'is_read': True})
        db.session.commit()
    
    # Get unread counts for all clients
    unread_counts = {}
    for client in clients:
        unread = Message.query.filter_by(
            user_id=client.id,
            is_admin=False,
            is_read=False
        ).count()
        unread_counts[client.id] = unread
    
    return render_template('admin/chat.html', 
                         clients=clients,
                         user=selected_user,
                         messages=messages,
                         unread_counts=unread_counts)

@app.route('/message/copy', methods=['POST'])
@login_required
def copy_message():
    message_id = request.form.get('message_id')
    message = Message.query.get(message_id)
    
    if message and (message.user_id == current_user.id or message.admin_id == current_user.id):
        return jsonify({'content': message.content})
    
    return jsonify({'error': 'Message not found'}), 404

@app.route('/message/resend', methods=['POST'])
@login_required
def resend_message():
    message_id = request.form.get('message_id')
    message = Message.query.get(message_id)
    
    if message:
        if message.user_id == current_user.id:  # Client resending
            new_message = Message(
                content=message.content,
                user_id=current_user.id,
                admin_id=None,
                is_admin=False
            )
        elif message.admin_id == current_user.id:  # Admin resending
            new_message = Message(
                content=message.content,
                user_id=message.user_id,
                admin_id=current_user.id,
                is_admin=True
            )
        else:
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.add(new_message)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Message not found'}), 404

@app.route('/delete/auto/<int:id>')
@login_required
def delete_auto_request(id):
    request_auto = AutoInsuranceRequest.query.get_or_404(id)
    if request_auto.user_id != current_user.id:
        abort(403)
    
    db.session.delete(request_auto)
    db.session.commit()
    flash('Your auto insurance request has been deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete/travel/<int:id>')
@login_required
def delete_travel_request(id):
    request_travel = TravelInsuranceRequest.query.get_or_404(id)
    if request_travel.user_id != current_user.id:
        abort(403)
    
    db.session.delete(request_travel)
    db.session.commit()
    flash('Your travel insurance request has been deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete/comesa/<int:id>')
@login_required
def delete_comesa_request(id):
    request_comesa = ComesaInsuranceRequest.query.get_or_404(id)
    if request_comesa.user_id != current_user.id:
        abort(403)
    
    db.session.delete(request_comesa)
    db.session.commit()
    flash('Your COMESA insurance request has been deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete/accident/<int:id>')
@login_required
def delete_accident_declaration(id):
    declaration = AccidentDeclaration.query.get_or_404(id)
    if declaration.user_id != current_user.id:
        abort(403)
    
    db.session.delete(declaration)
    db.session.commit()
    flash('Your accident declaration has been deleted!', 'success')
    return redirect(url_for('dashboard'))



# Admin routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get all requests with user data loaded
    auto_requests = AutoInsuranceRequest.query.options(db.joinedload(AutoInsuranceRequest.user)).all()
    travel_requests = TravelInsuranceRequest.query.options(db.joinedload(TravelInsuranceRequest.user)).all()
    comesa_requests = ComesaInsuranceRequest.query.options(db.joinedload(ComesaInsuranceRequest.user)).all()
    accident_declarations = AccidentDeclaration.query.options(db.joinedload(AccidentDeclaration.user)).all()
    
    # Get recent items for dashboard display
    recent_requests = (
        auto_requests[:5] + 
        travel_requests[:5] + 
        comesa_requests[:5]
    )[:5]  # Take only the 5 most recent
    
    recent_users = User.query.filter_by(role='client').order_by(User.created_at.desc()).limit(5).all()
    recent_accidents = AccidentDeclaration.query.order_by(AccidentDeclaration.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         auto_requests=auto_requests,
                         travel_requests=travel_requests,
                         comesa_requests=comesa_requests,
                         accident_declarations=accident_declarations,
                         recent_requests=recent_requests,
                         recent_users=recent_users,
                         recent_accidents=recent_accidents)

@app.route('/admin/manage-requests')
@login_required
@admin_required
def manage_requests():
    request_type = request.args.get('type', 'all')
    status = request.args.get('status', 'all')
    search = request.args.get('search', '')
    
    auto_query = AutoInsuranceRequest.query
    travel_query = TravelInsuranceRequest.query
    comesa_query = ComesaInsuranceRequest.query
    accident_query = AccidentDeclaration.query
    
    if status != 'all':
        auto_query = auto_query.filter_by(status=status)
        travel_query = travel_query.filter_by(status=status)
        comesa_query = comesa_query.filter_by(status=status)
        accident_query = accident_query.filter_by(status=status)
    
    if search:
        auto_query = auto_query.join(User).filter(
            (User.first_name.ilike(f'%{search}%')) |
            (User.last_name.ilike(f'%{search}%')) |
            (AutoInsuranceRequest.phone.ilike(f'%{search}%'))
        )
    
    if request_type == 'all' or request_type == 'auto':
        auto_requests = auto_query.all()
    else:
        auto_requests = []
    
    if request_type == 'all' or request_type == 'travel':
        travel_requests = travel_query.all()
    else:
        travel_requests = []
    
    if request_type == 'all' or request_type == 'comesa':
        comesa_requests = comesa_query.all()
    else:
        comesa_requests = []
    
    if request_type == 'all' or request_type == 'accident':
        accident_declarations = accident_query.all()
    else:
        accident_declarations = []
    
    return render_template('admin/manage_requests.html',
                         auto_requests=auto_requests,
                         travel_requests=travel_requests,
                         comesa_requests=comesa_requests,
                         accident_declarations=accident_declarations,
                         request_type=request_type,
                         status=status,
                         search=search)

@app.route('/admin/manage-users')
@login_required
@admin_required
def manage_users():
    search = request.args.get('search', '')
    
    if search:
        users = User.query.filter(
            (User.role == 'client') &
            ((User.first_name.ilike(f'%{search}%')) |
             (User.last_name.ilike(f'%{search}%')) |
             (User.email.ilike(f'%{search}%')) |
             (User.phone.ilike(f'%{search}%')))
        ).all()
    else:
        users = User.query.filter_by(role='client').all()
    
    return render_template('admin/manage_users.html', users=users, search=search)

# Admin actions
@app.route('/admin/approve/<string:type>/<int:id>')
@login_required
@admin_required
def approve_request(type, id):
    if type == 'auto':
        request = AutoInsuranceRequest.query.get_or_404(id)
    elif type == 'travel':
        request = TravelInsuranceRequest.query.get_or_404(id)
    elif type == 'comesa':
        request = ComesaInsuranceRequest.query.get_or_404(id)
    elif type == 'accident':
        request = AccidentDeclaration.query.get_or_404(id)
    else:
        abort(404)
    
    request.status = 'approved'
    db.session.commit()
    
    user = User.query.get(request.user_id)
    send_status_email(user.email, f'{type} request', 'approved')
    
    flash(f'The {type} request has been approved!', 'success')
    return redirect(url_for('manage_requests'))

@app.route('/admin/reject/<string:type>/<int:id>')
@login_required
@admin_required
def reject_request(type, id):
    if type == 'auto':
        request = AutoInsuranceRequest.query.get_or_404(id)
    elif type == 'travel':
        request = TravelInsuranceRequest.query.get_or_404(id)
    elif type == 'comesa':
        request = ComesaInsuranceRequest.query.get_or_404(id)
    elif type == 'accident':
        request = AccidentDeclaration.query.get_or_404(id)
    else:
        abort(404)
    
    request.status = 'rejected'
    db.session.commit()
    
    user = User.query.get(request.user_id)
    send_status_email(user.email, f'{type} request', 'rejected')
    
    flash(f'The {type} request has been rejected!', 'success')
    return redirect(url_for('manage_requests'))

@app.route('/download/auto/<int:id>') 
@login_required
def download_auto_request(id):
    request_auto = AutoInsuranceRequest.query.get_or_404(id)
    if request_auto.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    
    # Get the absolute path to the uploads directory
    uploads_dir = os.path.join(app.root_path,  'uploads', 'images')
    
    # Helper function to check if image exists and get its absolute path
    def get_image_path(filename):
        if not filename:
            return None
        image_path = os.path.join(uploads_dir, filename)
        if os.path.exists(image_path):
            return image_path
        return None
    
    # Get image paths
    carte_rose_path = get_image_path(request_auto.carte_rose)
    ancient_card_path = get_image_path(request_auto.ancient_card)
    
    # Render HTML with absolute file paths
    html = render_template(
        'client/pdf_auto_request.html', 
        request=request_auto,
        now=datetime.now(),
        carte_rose_path=carte_rose_path,
        ancient_card_path=ancient_card_path
    )
    
    # Create PDF with images
    pdf = BytesIO()
    
    # Custom link callback to handle file paths
    def link_callback(uri, rel):
        # Convert relative URIs to absolute system paths
        if uri.startswith('/uploads/images/'):
            path = os.path.join(app.root_path, uri[1:])
            if os.path.exists(path):
                return path
        return uri
    
    pisa_status = pisa.CreatePDF(html, dest=pdf, link_callback=link_callback)
    
    if pisa_status.err:
        current_app.logger.error("PDF generation error: %s", pisa_status.err)
        flash('Error generating PDF. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    
    pdf.seek(0)
    
    return send_file(
        pdf,
        as_attachment=True,
        download_name=f"auto_insurance_request_{request_auto.id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/download/travel/<int:id>')
@login_required
def download_travel_request(id):
    request_travel = TravelInsuranceRequest.query.get_or_404(id)
    if request_travel.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    
    # Get the absolute path to the uploads directory
    uploads_dir = os.path.join(app.root_path,  'uploads', 'images')
    
    # Helper function to check if image exists and get its absolute path
    def get_image_path(filename):
        if not filename:
            return None
        image_path = os.path.join(uploads_dir, filename)
        if os.path.exists(image_path):
            return image_path
        return None
    
    # Get image path
    passport_path = get_image_path(request_travel.passport)
    
    # Render HTML with absolute file paths
    html = render_template(
        'client/pdf_travel_request.html', 
        request=request_travel,
        now=datetime.now(),
        passport_path=passport_path
    )
    
    # Create PDF with images
    pdf = BytesIO()
    
    # Custom link callback to handle file paths
    def link_callback(uri, rel):
        # Convert relative URIs to absolute system paths
        if uri.startswith('/uploads/images/'):
            path = os.path.join(app.root_path, uri[1:])
            if os.path.exists(path):
                return path
        return uri
    
    pisa_status = pisa.CreatePDF(html, dest=pdf, link_callback=link_callback)
    
    if pisa_status.err:
        current_app.logger.error("PDF generation error: %s", pisa_status.err)
        flash('Error generating PDF. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    
    pdf.seek(0)
    
    return send_file(
        pdf,
        as_attachment=True,
        download_name=f"travel_insurance_request_{request_travel.id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/download/comesa/<int:id>') 
@login_required
def download_comesa_request(id):
    request_comesa = ComesaInsuranceRequest.query.get_or_404(id)
    if request_comesa.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    
    # Get the absolute path to the uploads directory
    uploads_dir = os.path.join(app.root_path,  'uploads', 'images')
    
    # Helper function to check if image exists and get its absolute path
    def get_image_path(filename):
        if not filename:
            return None
        image_path = os.path.join(uploads_dir, filename)
        if os.path.exists(image_path):
            return image_path
        return None
    
    # Get image paths
    carte_rose_path = get_image_path(request_comesa.carte_rose)
    ancient_card_path = get_image_path(request_comesa.ancient_card)
    
    # Render HTML with absolute file paths
    html = render_template(
        'client/pdf_comesa_request.html', 
        request=request_comesa,
        now=datetime.now(),
        carte_rose_path=carte_rose_path,
        ancient_card_path=ancient_card_path
    )
    
    # Create PDF with images
    pdf = BytesIO()
    
    # Custom link callback to handle file paths
    def link_callback(uri, rel):
        # Convert relative URIs to absolute system paths
        if uri.startswith('/uploads/images/'):
            path = os.path.join(app.root_path, uri[1:])
            if os.path.exists(path):
                return path
        return uri
    
    pisa_status = pisa.CreatePDF(html, dest=pdf, link_callback=link_callback)
    
    if pisa_status.err:
        current_app.logger.error("PDF generation error: %s", pisa_status.err)
        flash('Error generating PDF. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    
    pdf.seek(0)
    
    return send_file(
        pdf,
        as_attachment=True,
        download_name=f"comesa_insurance_request_{request_comesa.id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/download/accident/<int:id>')
@login_required
def download_accident_declaration(id):
    declaration = AccidentDeclaration.query.get_or_404(id)
    if declaration.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    
    # Get the absolute path to the uploads directory
    uploads_dir = os.path.join(app.root_path,  'uploads', 'images')
    
    # Helper function to check if image exists and get its absolute path
    def get_image_path(filename):
        if not filename:
            return None
        image_path = os.path.join(uploads_dir, filename)
        if os.path.exists(image_path):
            return image_path
        return None
    
    # Prepare image paths
    image_paths = {}
    image_fields = [
        'accident_image1', 'accident_image2', 'accident_image3',
        'carte_rose_image', 'insurance_card_image', 'driving_license_image'
    ]
    
    for field in image_fields:
        filename = getattr(declaration, field)
        image_paths[field] = get_image_path(filename)
    
    # Render HTML with absolute file paths
    html = render_template(
        'client/pdf_accident_declaration.html', 
        declaration=declaration,
        now=datetime.now(),
        image_paths=image_paths
    )
    
    # Create PDF with images
    pdf = BytesIO()
    
    # Custom link callback to handle file paths
    def link_callback(uri, rel):
        # Convert relative URIs to absolute system paths
        if uri.startswith('/uploads/images/'):
            path = os.path.join(app.root_path, uri[1:])
            if os.path.exists(path):
                return path
        return uri
    
    pisa_status = pisa.CreatePDF(html, dest=pdf, link_callback=link_callback)
    
    if pisa_status.err:
        current_app.logger.error("PDF generation error: %s", pisa_status.err)
        flash('Error generating PDF. Please try again.', 'danger')
        return redirect(url_for('dashboard'))
    
    pdf.seek(0)
    
    return send_file(
        pdf,
        as_attachment=True,
        download_name=f"accident_declaration_{declaration.id}.pdf",
        mimetype='application/pdf'
    )


@app.route('/admin/download/<string:type>/<int:id>')
@login_required
@admin_required
def download_request(type, id):
    if type == 'auto':
        request_obj = AutoInsuranceRequest.query.get_or_404(id)
        filename = f"auto_insurance_{id}.pdf"
        template = 'admin/pdf_auto_request.html'
        images = {
            'carte_rose': get_image_path(request_obj.carte_rose),
            'ancient_card': get_image_path(request_obj.ancient_card)
        }

        def link_callback(uri, _):
            if uri == request_obj.carte_rose:
                return images['carte_rose']
            elif uri == request_obj.ancient_card:
                return images['ancient_card']
            return None

        data = {'request': request_obj, 'now': datetime.now(), 'current_user': current_user, 'images': images}

    elif type == 'comesa':
        request_obj = ComesaInsuranceRequest.query.get_or_404(id)
        filename = f"comesa_insurance_{id}.pdf"
        template = 'admin/pdf_comesa_request.html'
        images = {
            'carte_rose': get_image_path(request_obj.carte_rose),
            'ancient_card': get_image_path(request_obj.ancient_card)
        }

        def link_callback(uri, _):
            if uri == request_obj.carte_rose:
                return images['carte_rose']
            elif uri == request_obj.ancient_card:
                return images['ancient_card']
            return None

        data = {'request': request_obj, 'now': datetime.now(), 'current_user': current_user, 'images': images}

    elif type == 'travel':
        request_obj = TravelInsuranceRequest.query.get_or_404(id)
        filename = f"travel_insurance_{id}.pdf"
        template = 'admin/pdf_travel_request.html'
        images = {'passport': get_image_path(request_obj.passport)}

        def link_callback(uri, _):
            if uri == request_obj.passport:
                return images['passport']
            return None

        data = {'request': request_obj, 'now': datetime.now(), 'current_user': current_user, 'images': images}

    elif type == 'accident':
        declaration = AccidentDeclaration.query.get_or_404(id)
        user = declaration.user
        auto_requests = AutoInsuranceRequest.query.filter_by(user_id=user.id).all()
        travel_requests = TravelInsuranceRequest.query.filter_by(user_id=user.id).all()
        comesa_requests = ComesaInsuranceRequest.query.filter_by(user_id=user.id).all()

        filename = f"accident_declaration_{id}_with_client_models.pdf"
        template = 'admin/pdf_accident_declaration.html'

        image_fields = [
            'accident_image1', 'accident_image2', 'accident_image3',
            'carte_rose_image', 'insurance_card_image', 'driving_license_image'
        ]
        images = {field: get_image_path(getattr(declaration, field)) for field in image_fields}

        def link_callback(uri, _):
            for field in image_fields:
                filename = getattr(declaration, field)
                if filename and uri == filename:
                    return images[field]
            return None

        data = {
            'declaration': declaration,
            'now': datetime.now(),
            'current_user': current_user,
            'user': user,
            'auto_requests': auto_requests,
            'travel_requests': travel_requests,
            'comesa_requests': comesa_requests,
            'images': images
        }

    else:
        abort(404)

    # Render and generate
    html = render_template(template, **data)
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf, link_callback=link_callback)

    if pisa_status.err:
        flash('Error generating PDF. Please try again.', 'danger')
        return redirect(url_for('manage_requests'))

    pdf.seek(0)
    return send_file(pdf, as_attachment=True,
        download_name=filename,
        mimetype='application/pdf'
    )

def get_image_path(filename):
    """
    Return a base64 data URI of the image for embedding in PDF,
    or None if missing.
    """
    if not filename:
        return None

    upload_folder = os.path.join(os.getcwd(), "uploads/images")  # adjust if different
    file_path = os.path.join(upload_folder, filename)

    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
            ext = os.path.splitext(file_path)[1][1:].lower()  # e.g. 'png', 'jpg'
            return f"data:image/{ext};base64,{encoded}"
    return None



# Error handlers
@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def page_not_found(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('errors/500.html'), 500

# Context processors
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user_to_delete.id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('manage_users'))
    
    try:
        # Delete all related records first to maintain referential integrity
        Message.query.filter((Message.user_id == user_id) | (Message.admin_id == user_id)).delete()
        AutoInsuranceRequest.query.filter_by(user_id=user_id).delete()
        TravelInsuranceRequest.query.filter_by(user_id=user_id).delete()
        ComesaInsuranceRequest.query.filter_by(user_id=user_id).delete()
        AccidentDeclaration.query.filter_by(user_id=user_id).delete()
        
        # Finally delete the user
        db.session.delete(user_to_delete)
        db.session.commit()
        
        flash(f'User {user_to_delete.email} has been deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the user. Please try again.', 'danger')
        app.logger.error(f'Error deleting user {user_id}: {str(e)}')
    
    return redirect(url_for('manage_users'))



@app.route('/admin/view/<string:type>/<int:id>')
@login_required
@admin_required
def view_request(type, id):
    if type == 'auto':
        request = AutoInsuranceRequest.query.get_or_404(id)
        template = 'admin/view_auto_request.html'
    elif type == 'travel':
        request = TravelInsuranceRequest.query.get_or_404(id)
        template = 'admin/view_travel_request.html'
    elif type == 'comesa':
        request = ComesaInsuranceRequest.query.get_or_404(id)
        template = 'admin/view_comesa_request.html'
    elif type == 'accident':
        request = AccidentDeclaration.query.get_or_404(id)
        template = 'admin/view_accident_request.html'
    else:
        abort(404)
    
    return render_template(template, request=request, type=type)

@app.after_request
def after_request(response):
    # Add headers to prevent caching for mobile devices
    user_agent = request.headers.get('User-Agent', '').lower()
    is_mobile = any(device in user_agent for device in ['mobile', 'android', 'iphone', 'ipad', 'ipod'])
    
    if is_mobile:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
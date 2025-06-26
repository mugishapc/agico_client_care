import base64
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, IntegerField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_uploads import UploadSet, configure_uploads, IMAGES, DOCUMENTS
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
from functools import wraps
from config import Config
from xhtml2pdf import pisa
from io import BytesIO
import logging
from flask import current_app, Response
from flask_mail import Mail, Message as MailMessage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "bic_client_care.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'mugishapc1@gmail.com'
app.config['MAIL_PASSWORD'] = 'oljteuieollgwxxf'
app.config['MAIL_DEFAULT_SENDER'] = 'mugishapc1@gmail.com'

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
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default='client')  # 'client' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    auto_insurance_requests = db.relationship('AutoInsuranceRequest', back_populates='user', lazy=True)
    travel_insurance_requests = db.relationship('TravelInsuranceRequest', back_populates='user', lazy=True)
    comesa_insurance_requests = db.relationship('ComesaInsuranceRequest', back_populates='user', lazy=True)
    accident_declarations = db.relationship('AccidentDeclaration', back_populates='user', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.user_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.admin_id', backref='admin', lazy=True)
    
    def __repr__(self):
        return f'<User {self.email}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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
    db.create_all()

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
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
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
            
            flash('Your account has been created! You can now log in.', 'success')
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
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    
    return render_template('auth/login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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
        flash('Your accident declaration has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('client/declare_accident.html', form=form)

@app.route('/branches')
@login_required
def branches():
    branches_list = [
        {'name': 'BIC SIEGE', 'phone': '+25762555777'},
        {'name': 'AGENCE KAMENGE', 'phone': '+25762555777'},
        {'name': 'AGENCE KINAMA', 'phone': '+25762555777'},
        {'name': 'AGENCE CARAMA', 'phone': '+25762555777'},
        {'name': 'AGENCE NGOZI', 'phone': '+25762555777'},
        {'name': 'AGENCE KIRUNDO', 'phone': '+25762555777'},
        {'name': 'AGENCE MUYINGA', 'phone': '+25762555777'},
        {'name': 'AGENCE RUYIGI', 'phone': '+25762555777'},
        {'name': 'AGENCE KAYANZA', 'phone': '+25762555777'},
        {'name': 'AGENCE RUBIRIZI', 'phone': '+25762555777'},
        {'name': 'AGENCE GITEGA', 'phone': '+25762555777'},
        {'name': 'AGENCE RUTANA', 'phone': '+25762555777'},
        {'name': 'AGENCE MWARO', 'phone': '+25762555777'},
        {'name': 'GLOBAL SUPPORT', 'phone': '+25762555777'}
    ]
    return render_template('client/branches.html', branches=branches_list)

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    if request.method == 'POST':
        content = request.form.get('message')
        new_message = Message(
            content=content,
            user_id=current_user.id,
            admin_id=None,
            is_admin=False
        )
        db.session.add(new_message)
        db.session.commit()
    
    messages = Message.query.filter(
        (Message.user_id == current_user.id) |
        (Message.admin_id == current_user.id)
    ).order_by(Message.created_at).all()
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
            content = request.form.get('message')
            new_message = Message(
                content=content,
                user_id=user_id,
                admin_id=current_user.id,
                is_admin=True
            )
            db.session.add(new_message)
            db.session.commit()
        
        messages = Message.query.filter(
            (Message.user_id == user_id) |
            ((Message.admin_id == current_user.id) & (Message.user_id == user_id))
        ).order_by(Message.created_at).all()
    
    return render_template('admin/chat.html', 
                         clients=clients,
                         user=selected_user,
                         messages=messages)

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

@app.route('/download/auto/<int:id>')
@login_required
def download_auto_request(id):
    request_auto = AutoInsuranceRequest.query.get_or_404(id)
    if request_auto.user_id != current_user.id:
        abort(403)
    
    # Get absolute paths to images
    carte_rose_path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], request_auto.carte_rose) if request_auto.carte_rose else None
    ancient_card_path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], request_auto.ancient_card) if request_auto.ancient_card else None
    
    # Convert images to data URIs if they exist
    def image_to_data_uri(image_path):
        if image_path and os.path.exists(image_path):
            with open(image_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                return f"data:image/{image_path.split('.')[-1]};base64,{encoded_string}"
        return None
    
    html = render_template('client/pdf_auto_request.html', 
                         request=request_auto,
                         carte_rose_uri=image_to_data_uri(carte_rose_path),
                         ancient_card_uri=image_to_data_uri(ancient_card_path))
    
    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)
    pdf.seek(0)
    
    return send_file(
        pdf,
        as_attachment=True,
        download_name=f"auto_insurance_request_{request_auto.id}.pdf",
        mimetype='application/pdf'
    )

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

# Utility functions
def send_confirmation_email(to, subject_suffix):
    msg = Message(
        subject=f'BIC Client Care - {subject_suffix} Received',
        recipients=[to],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = f'''
    Thank you for your {subject_suffix.lower()}.
    
    We have received your submission and will process it shortly.
    You can check the status in your BIC Client Care dashboard.
    
    Best regards,
    BIC Client Care Team
    '''
    mail.send(msg)

def send_status_email(to, request_type, status):
    msg = Message(
        subject=f'BIC Client Care - {request_type.capitalize()} {status.capitalize()}',
        recipients=[to],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = f'''
    Your {request_type} has been {status}.
    
    You can view the details in your BIC Client Care dashboard.
    
    Best regards,
    BIC Client Care Team
    '''
    mail.send(msg)

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

@app.route('/download/travel/<int:id>')
@login_required
def download_travel_request(id):
    request_travel = TravelInsuranceRequest.query.get_or_404(id)
    if request_travel.user_id != current_user.id:
        abort(403)
    
    # Get absolute path to passport image
    passport_path = None
    if request_travel.passport:  # Check if passport field has a value
        # Construct the full path to the uploaded image
        upload_folder = current_app.config['UPLOADED_IMAGES_DEST']
        passport_path = os.path.join(upload_folder, request_travel.passport)
    
    # Convert image to data URI if it exists
    def image_to_data_uri(image_path):
        if image_path and os.path.exists(image_path):
            with open(image_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                # Get file extension for proper MIME type
                ext = os.path.splitext(image_path)[1].lower().replace('.', '')
                if ext == 'jpg':
                    ext = 'jpeg'  # Correct MIME type for JPEG
                return f"data:image/{ext};base64,{encoded_string}"
        return None
    
    passport_uri = image_to_data_uri(passport_path)
    
    html = render_template('client/pdf_travel_request.html', 
                         request=request_travel,
                         now=datetime.now(),
                         passport_uri=passport_uri)
    
    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)
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
    if request_comesa.user_id != current_user.id:
        abort(403)
    
    # Prepare image data
    image_data = {
        'carte_rose': None,
        'ancient_card': None
    }
    
    # Helper function to get image data
    def get_image_data(filename):
        if not filename:
            return None
        try:
            image_path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename)
            if os.path.exists(image_path):
                with open(image_path, 'rb') as f:
                    return base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"Error processing image {filename}: {e}")
        return None
    
    # Get image data
    image_data['carte_rose'] = get_image_data(request_comesa.carte_rose)
    image_data['ancient_card'] = get_image_data(request_comesa.ancient_card)
    
    # Render HTML with image data
    html = render_template(
        'client/pdf_comesa_request.html', 
        request=request_comesa,
        now=datetime.now(),
        images=image_data
    )
    
    # Create PDF
    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)
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
    if declaration.user_id != current_user.id:
        abort(403)
    
    # Prepare image data
    image_fields = [
        'accident_image1', 'accident_image2', 'accident_image3',
        'carte_rose_image', 'insurance_card_image', 'driving_license_image'
    ]
    image_data = {}
    
    for field in image_fields:
        filename = getattr(declaration, field)
        if filename:
            try:
                image_path = os.path.join(app.config['UPLOADED_IMAGES_DEST'], filename)
                if os.path.exists(image_path):
                    with open(image_path, 'rb') as f:
                        encoded_string = base64.b64encode(f.read()).decode('utf-8')
                        ext = os.path.splitext(filename)[1].lower().replace('.', '')
                        if ext == 'jpg':
                            ext = 'jpeg'
                        image_data[field] = f"data:image/{ext};base64,{encoded_string}"
            except Exception as e:
                current_app.logger.error(f"Error processing image {filename}: {e}")
                image_data[field] = None
        else:
            image_data[field] = None
    
    # Render HTML with image data
    html = render_template(
        'client/pdf_accident_declaration.html', 
        declaration=declaration,
        now=datetime.now(),
        images=image_data
    )
    
    # Create PDF
    pdf = BytesIO()
    pisa.CreatePDF(html, dest=pdf)
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
        request = AutoInsuranceRequest.query.get_or_404(id)
        filename = f"auto_insurance_{id}.pdf"
        data = {
            'Type': 'Auto Insurance',
            'Client': f"{request.user.first_name} {request.user.last_name}",
            'Phone': request.phone,
            'Car Make': request.car_make,
            'Car Model': request.car_model,
            'Year': request.year,
            'VIN': request.vin,
            'Status': request.status,
            'Date': request.created_at.strftime('%Y-%m-%d')
        }
    elif type == 'travel':
        request = TravelInsuranceRequest.query.get_or_404(id)
        filename = f"travel_insurance_{id}.pdf"
        data = {
            'Type': 'Travel Insurance',
            'Client': f"{request.user.first_name} {request.user.last_name}",
            'Destination': request.destination,
            'Departure Date': request.departure_date.strftime('%Y-%m-%d'),
            'Return Date': request.return_date.strftime('%Y-%m-%d'),
            'Days': request.days,
            'Travelers': request.travelers,
            'Status': request.status,
            'Date': request.created_at.strftime('%Y-%m-%d')
        }
    elif type == 'comesa':
        request = ComesaInsuranceRequest.query.get_or_404(id)
        filename = f"comesa_insurance_{id}.pdf"
        data = {
            'Type': 'COMESA Insurance',
            'Client': f"{request.user.first_name} {request.user.last_name}",
            'Phone': request.phone,
            'Company': request.company,
            'TIN': request.tin,
            'Vehicle Details': request.vehicle_details,
            'Status': request.status,
            'Date': request.created_at.strftime('%Y-%m-%d')
        }
    elif type == 'accident':
        request = AccidentDeclaration.query.get_or_404(id)
        filename = f"accident_declaration_{id}.pdf"
        data = {
            'Type': 'Accident Declaration',
            'Client': f"{request.user.first_name} {request.user.last_name}",
            'Accident Date': request.accident_date.strftime('%Y-%m-%d'),
            'Car Type': request.car_type,
            'Plate License': request.plate_license,
            'Location': request.location,
            'Description': request.description,
            'Status': request.status,
            'Date': request.created_at.strftime('%Y-%m-%d')
        }
    else:
        abort(404)
    
    # Generate PDF
    pdf = generate_pdf(data)
    
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

def generate_pdf(data):
    # Create a PDF using reportlab or other library
    # This is a simplified version - you'll need to implement properly
    from io import BytesIO
    from reportlab.pdfgen import canvas
    
    buffer = BytesIO()
    p = canvas.Canvas(buffer)
    
    y = 800
    p.drawString(100, y, "BIC Client Care - Request Details")
    y -= 30
    
    for key, value in data.items():
        p.drawString(100, y, f"{key}: {value}")
        y -= 20
    
    p.showPage()
    p.save()
    
    buffer.seek(0)
    return buffer.getvalue()

# Utility functions
def send_confirmation_email(to, subject_suffix):
    msg = MailMessage(
        subject=f'BIC Client Care - {subject_suffix} Received',
        recipients=[to],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = f'''
    Thank you for your {subject_suffix.lower()}.
    
    We have received your submission and will process it shortly.
    You can check the status in your BIC Client Care dashboard.
    
    Best regards,
    BIC Client Care Team
    '''
    mail.send(msg)

def send_status_email(to, request_type, status):
    msg = MailMessage(
        subject=f'BIC Client Care - {request_type.capitalize()} {status.capitalize()}',
        recipients=[to],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.body = f'''
    Your {request_type} has been {status}.
    
    You can view the details in your BIC Client Care dashboard.
    
    Best regards,
    BIC Client Care Team
    '''
    mail.send(msg)



if __name__ == '__main__':
    app.run(debug=True)
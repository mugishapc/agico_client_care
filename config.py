import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///instance/bic_client_care.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email configuration
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'mugishapc1@gmail.com'
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'oljteuieollgwxxf'
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'mugishapc1@gmail.com'

    # File uploads
    UPLOADED_IMAGES_DEST = 'static/uploads/images'
    UPLOADED_DOCS_DEST = 'static/uploads/documents'
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    ALLOWED_DOC_EXTENSIONS = {'pdf', 'doc', 'docx'}
   
    # Admin credentials
    ADMIN_EMAIL = 'mugishapc1@gmail.com'
    ADMIN_PASSWORD = '0220Mpc.'
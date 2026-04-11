import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'clavesecreta123') 
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    DATABASE = os.getenv('DATABASE_PATH', 'database.db')
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] =  'sqlite:///database.db'
db = SQLAlchemy(app)

app.config['KEY'] = 'this_is_key'

from server import routes
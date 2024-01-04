from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_migrate import Migrate
from flask_restful import Resource, Api
from flasgger import Swagger


app = Flask(__name__)
with app.app_context():
    swagger = Swagger(app)
    
    app.config.from_object(Config)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hotelReservationDatabase.db'
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


    CORS(app) #Middle for cross-origin web request from client repo

    db = SQLAlchemy(app)
    migrate = Migrate(app, db)
    api = Api(app)
    from . import admin
    from hotelReservation.endPoints.General import accounts
from hotelReservation import db, app
from functools import wraps
import jwt
from flask import jsonify, request
from werkzeug.security import generate_password_hash
import uuid

       
          # one to many relationship
# each user can be part of many organization and have a specific Positions
Item_SubOrder = db.Table('Item_SubOrder',
                    db.Column('SubOrder', db.Integer, db.ForeignKey('SubOrder.id')),
                    db.Column('Item', db.Integer, db.ForeignKey('Item.id'))
                    )      
                    

# models
class Users(db.Model):
    __tablename__ = 'Users'
    # account ID
    id = db.Column(db.String(150), primary_key=True)

    # login creds
    email = db.Column(db.String(120), nullable=False)
    passwordHash = db.Column(db.String(120), nullable=False)

    # user personal details
    firstName = db.Column(db.String(120), nullable=False)
    lastName = db.Column(db.String(120), nullable=False)

    def __init__(self,email,firstName,lastName,password):
        self.email=email
        self.firstName = firstName
        self.lastName = lastName
        self.passwordHash = generate_password_hash(password, method='sha256')  
        self.id = str(uuid.uuid4())

    def CheckPassword(self,password):
        return (self.passwordHash == generate_password_hash(password, method='sha256'))
    
    # session token handler
    def token_required(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            token = None
            if 'x-access-tokens' in request.headers:
                token = request.headers['x-access-tokens']
        
            if not token:
                return jsonify({'message': 'a valid token is missing'})
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = Users.query.filter_by(public_id=data['public_id']).first()
            except:
                return jsonify({'message': 'token is invalid'})
        
            return f(current_user, *args, **kwargs)
        return decorator


    def __repr__(self):
        return '<User %r>' % self.lastName+","+self.firstName

class Employee(Users):
    __tablename__ = 'Employee'
    restaurant = db.Column(db.String(120), nullable=False)
    position = db.Column(db.String(120), nullable=False)
    
    def __init__(self, email, firstName, lastName, password,restaurant,position):
        super().__init__(email, firstName, lastName, password)
        self.restaurant = restaurant
        self.position = position
        
class Customer(Users):
    __tablename__ = 'Customer'
    
    def __init__(self, email, firstName, lastName, password):
        super().__init__(email, firstName, lastName, password)

class Admin(Users):
    __tablename__ = 'Admin'
    
    def __init__(self, email, firstName, lastName, password):
        super().__init__(email, firstName, lastName, password)


class Restaurants(db.Model):
    __tablename__ = 'Restaurants'
    # account ID
    id = db.Column(db.String(150), primary_key=True)
    name = db.Column(db.String(120), nullable=False)

    def __init__(self,name):
        self.name = name
        self.id = str(uuid.uuid4())
        
         
class Table(db.Model):
    __tablename__ = 'Table'

    id = db.Column(db.String(150), primary_key=True)
    name = db.Column(db.String(120), nullable=False)

    def __init__(self,name):
        self.name = name
        self.id = str(uuid.uuid4())
        
class Order(db.Model):
    __tablename__ = 'Order'

    id = db.Column(db.String(150), primary_key=True)
    table = db.Column(db.String(150), nullable=False)

    def __init__(self,table):
        self.table = table
        self.id = str(uuid.uuid4())
        
class SubOrder(db.Model):
    __tablename__ = 'SubOrder'

    id = db.Column(db.String(150), primary_key=True)
    order = db.Column(db.String(150), nullable=False)
    table = db.Column(db.String(150), nullable=False)
    items = db.relationship('Item', secondary="Item_SubOrder", backref='SubOrder')

    def __init__(self,table,order):
        self.order = order
        self.table = table
        self.id = str(uuid.uuid4())
        
class Item(db.Model):
    __tablename__ = 'Item'

    id = db.Column(db.String(150), primary_key=True)
    category = db.Column(db.String(150), nullable=False)
    cost = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=False)
    imagePath = db.Column(db.Text, nullable=False)

    def __init__(self,category,cost,description,imagePath):
        self.category = category
        self.cost = cost
        self.description = description
        self.imagePath = imagePath
        self.id = str(uuid.uuid4())
        
class Category(db.Model):
    __tablename__ = 'Category'

    id = db.Column(db.String(150), primary_key=True)
    name = db.Column(db.String(120), nullable=False)

    def __init__(self,name):
        self.name = name
        self.id = str(uuid.uuid4())
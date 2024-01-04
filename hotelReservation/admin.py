from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from hotelReservation import db, app
from hotelReservation.models import *

class UserView(ModelView):
    column_list = ('id', 'email')





if app.debug:
    admin = Admin(app)
    '''
    Register models to the admin view
    '''

    admin.add_view( UserView(Users,db.session))

    
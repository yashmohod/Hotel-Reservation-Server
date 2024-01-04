from flask_admin.contrib.sqla import ModelView
from flask_admin import Admin
from anzen import db, app
from anzen.models import *

class UserView(ModelView):
    column_list = ('id', 'email')





if app.debug:
    admin = Admin(app)
    '''
    Register models to the admin view
    '''

    admin.add_view( UserView(Users,db.session))
    admin.add_view( ModelView(incident,db.session))
    admin.add_view( ModelView(location,db.session))
    admin.add_view( ModelView(saspIncidentReport,db.session))
    admin.add_view( ModelView(saspReferral,db.session))
    admin.add_view( ModelView(timeCard,db.session))
    admin.add_view( ModelView(clockedIn,db.session))
    admin.add_view( ModelView(organizations,db.session))
    admin.add_view( ModelView(orgNpos,db.session))
    admin.add_view( ModelView(features,db.session))
    admin.add_view( ModelView(featuresPermissions,db.session))
    admin.add_view( ModelView(shifts,db.session))
    admin.add_view( ModelView(promoteTo,db.session))
    admin.add_view( ModelView(demoteTo,db.session))
    
from datetime import date
from typing import List
from typing import List
from anzen import db, app
from functools import wraps
import jwt
from flask import jsonify, request
from werkzeug.security import generate_password_hash
import uuid
import datetime


# tables

# one to many relationship
# each user can be part of many organization and have a specific Positions
user_orgNpos = db.Table('user_orgNpos',
                    db.Column('Users', db.Integer, db.ForeignKey('Users.id')),
                    db.Column('orgNpos', db.Integer, db.ForeignKey('orgNpos.id'))
                    )
# one to many relationship
# each user will have a permission for every features
user_featuresPermissions = db.Table('user_featuresPermissions',
                    db.Column('Users', db.Integer, db.ForeignKey('Users.id')),
                    db.Column('featuresPermissions', db.Integer, db.ForeignKey('featuresPermissions.id'))
                    )
# one to many relationship
# every position in an organization will have a permission for every feature
orgNpos_featuresPermissions = db.Table('orgNpos_featuresPermissions',
                    db.Column('orgNpos', db.Integer, db.ForeignKey('orgNpos.id')),
                    db.Column('featuresPermissions', db.Integer, db.ForeignKey('featuresPermissions.id'))
                    )
# one to many relationship
# every position will be related to other position to which they can be promoted 
orgNpos_promote = db.Table('orgNpos_promote',
                    db.Column('orgNpos', db.Integer, db.ForeignKey('orgNpos.id')),
                    db.Column('promoteTo', db.Integer, db.ForeignKey('promoteTo.id'))
                    )
# one to many relationship
# every position will be related to other position to which they can be demoted 
orgNpos_demote = db.Table('orgNpos_demote',
                    db.Column('orgNpos', db.Integer, db.ForeignKey('orgNpos.id')),
                    db.Column('demoteTo', db.Integer, db.ForeignKey('demoteTo.id'))
                    )
"""
Note: each user initially will be assigned 
"""
                  
                
                    

# models
class Users(db.Model):
    __tablename__ = 'Users'
    # account ID
    id = db.Column(db.String(150), primary_key=True)

    # login creds
    email = db.Column(db.String(120), nullable=False)
    # passwordHash = db.Column(db.String(120), nullable=False)

    # user personal details
    firstName = db.Column(db.String(120), nullable=False)
    lastName = db.Column(db.String(120), nullable=False)
    collegeId = db.Column(db.Integer, nullable=False)
    dob = db.Column(db.String(120), nullable=False)

    # user orgatnization details
    # status = db.Column(db.Boolean, nullable=False)
    orgNpos = db.relationship('orgNpos', secondary="user_orgNpos", backref='Users')

    # user features and permissions
    featurePermissions = db.relationship('featuresPermissions', secondary="user_featuresPermissions", backref='Users')


    # status = db.Column(db.Boolean, nullable=False)
    orgNpos = db.relationship('orgNpos', secondary="user_orgNpos", backref='Users')



    # relations
    incidentReports = db.relationship('saspIncidentReport', backref='Users', lazy=True)

    def __init__(self,email,firstName,lastName,collegeId,dob):
        self.email=email
        self.firstName = firstName
        self.lastName = lastName
        self.collegeId = collegeId
        self.dob = dob
        self.id = str(uuid.uuid4())

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



class organizations(db.Model):
    __tablename__ = 'organizations'
    id = db.Column(db.String(150), primary_key=True)
    OrgName = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<OrgName %r>' % self.OrgName

class orgNpos(db.Model):
    __tablename__ = 'orgNpos'
    id = db.Column(db.String(150), primary_key=True)
    OrgName = db.Column(db.String(120), nullable=False)
    PosName = db.Column(db.String(120), nullable=False)
    title = db.Column(db.String(120), nullable=True)

    """
     number of available positions
     only a set number of employees can take a position by default
     but if set to -1 there is no limit 
    """
    availableNoPos = db.Column(db.Integer(), nullable=True)
    
    featurePermissions = db.relationship('featuresPermissions', secondary="orgNpos_featuresPermissions", backref='orgNpos')
    

    def __repr__(self):
        op = str(self.PosName)+"_"+str(self.OrgName)
        return op
    
class promoteTo(db.Model):
    __tablename__ = 'promoteTo'
    id = db.Column(db.String(150), primary_key=True)
    promoteFrom  = db.Column(db.String(150), db.ForeignKey('orgNpos.id'))
    nextPos = db.relationship('orgNpos', secondary="orgNpos_promote", backref='promoteTo')


class demoteTo(db.Model):
    __tablename__ = 'demoteTo'
    id = db.Column(db.String(150), primary_key=True)
    demoteFrom  = db.Column(db.String(150), db.ForeignKey('orgNpos.id'))
    nextPos = db.relationship('orgNpos', secondary="orgNpos_demote", backref='demoteTo')



class features(db.Model):
    __tablename__ = 'features'
    id = db.Column(db.String(150), primary_key=True)
    featureName = db.Column(db.String(120), nullable=False)
    org = db.Column(db.String(120), nullable=False)
    dashboardFeature = db.Column(db.Boolean, nullable=False)
    internallyManaged = db.Column(db.Boolean, nullable=False)
    internalUrl  = db.Column(db.String(120),nullable=False)
    externalUrl = db.Column(db.String(120),nullable=False)
    permissionManagement = db.Column(db.Boolean, nullable=False)
    featuresPermissions = db.relationship('featuresPermissions', backref='features')
    

    def __repr__(self):
        return '<feature %r>' % self.featureName

class featuresPermissions(db.Model):
    __tablename__ = 'featuresPermissions'
    id = db.Column(db.String(150), primary_key=True)
    featureId  = db.Column(db.String(150), db.ForeignKey('features.id'))
    featureName = db.Column(db.String(150), nullable=False)
    view = db.Column(db.Boolean, nullable=False)
    create = db.Column(db.Boolean, nullable=False)
    edit = db.Column(db.Boolean, nullable=False)
    delete = db.Column(db.Boolean, nullable=False)
    blackListed =  db.Column(db.Boolean, nullable=False)
    # identifiers
    ownerID = db.Column(db.String(150),nullable=False)
    userPerm = db.Column(db.Boolean, nullable=False)
    who = db.Column(db.String(250), nullable=False) # not really needed but for admin view pouposes only


    def __repr__(self):
        whoWhat = self.who +" " + self.featureName
        return '<whoWhat %r>' % whoWhat




class incident (db.Model):
    __tablename__ = 'incident'
    id = db.Column(db.String(150), primary_key=True)
    incidentName = db.Column(db.String(120), nullable=False)
    def __repr__(self):
        return '<inceident %r>' % self.incidentName


class location (db.Model):
    __tablename__ = 'location'
    id = db.Column(db.String(150), primary_key=True)
    locationName = db.Column(db.String(120), nullable=False)
    def __repr__(self):
        return '<location %r>' % self.locationName
    
class disciplinaryActions (db.Model):
    __tablename__ = 'disciplinaryAction'
    id = db.Column(db.String(150), primary_key=True)
    disciplinaryActionName = db.Column(db.String(120), nullable=False)
    orgName = db.Column(db.String(150))

    def __repr__(self):
        return '<location %r>' % self.locationName
    
class disciplinaryRecords (db.Model):
    __tablename__ = 'disciplinaryRecords'
    id = db.Column(db.String(150), primary_key=True)
    # person filing the disciplinaryRecords
    reportedByID  = db.Column(db.String(150),nullable=False)
    reportedByName = db.Column(db.String(120), nullable=False) 
    # person the disciplinaryRecords is about
    reportedOfID  = db.Column(db.String(150),nullable=False)
    reportedOfName = db.Column(db.String(120), nullable=False) 
    date = db.Column(db.DateTime, nullable=False)
    disciplinaryActionsName = db.Column(db.String(120), nullable=False)
    suspendable = db.Column(db.Boolean, nullable=False)
    suspendableDurationDays = db.Column(db.Integer, nullable=True)
    note = db.Column(db.Text, nullable=False)
    orgName = db.Column(db.String(150))
    def __repr__(self):
        return '<location %r>' % self.locationName


class saspIncidentReport (db.Model):
    __tablename__ = 'saspIncidentReport'
    id = db.Column(db.String(150), primary_key=True)
    reportedByID  = db.Column(db.String(150), db.ForeignKey('Users.id'),nullable=False)
    reportedByName = db.Column(db.String(120), nullable=False) 
    incident = db.Column(db.String(120), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    receivedTime = db.Column(db.String(120), nullable=False)
    enrouteTime = db.Column(db.String(120), nullable=False)
    arivedTime = db.Column(db.String(120), nullable=False)
    clearTime = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(120), nullable=False)
    locationDetail = db.Column(db.String(120), nullable=False)
    summary = db.Column(db.Text, nullable=False)

    # relations
    referrals = db.relationship('saspReferral', backref='incRep', lazy=True)

    def __repr__(self):
        return '<saspIncidentReport %r>' % str(self.incident)+","+str(self.date.date())
    

class saspReferral (db.Model):
    __tablename__ = 'saspReferral'
    id = db.Column(db.String(150), primary_key=True)

    # related sasp incidentReport
    incidentReport  = db.Column(db.String(150), db.ForeignKey('saspIncidentReport.id'),nullable=False)
    
    # inceident details
    incident = db.Column(db.String(120),nullable=False)
    location = db.Column(db.String(150), nullable=False)
    date = db.Column(db.Date(),nullable=False)
    judicialReferal = db.Column(db.Boolean, nullable=False)
    
    # person's details
    firstName = db.Column(db.String(120), nullable=False)
    lastName = db.Column(db.String(120), nullable=False)
    middleInitial = db.Column(db.String(120), nullable=False)
    ICID = db.Column(db.Integer, nullable=False)
    dob = db.Column(db.Date, nullable=False)
    address = db.Column(db.Text, nullable=False)
    phoneNo = db.Column(db.String(120), nullable=False)


    def __repr__(self):
        return '<saspReferral %r>' % self.firstName+","+self.incident


class timeCard (db.Model):
    __tablename__ = 'timeCard'
    id = db.Column(db.String(150), primary_key=True)

    who = db.Column(db.String(120), db.ForeignKey('Users.id'),nullable=False)
    whoName = db.Column(db.String(120), nullable=False)
    start = db.Column(db.DateTime(),nullable=False)
    end = db.Column(db.DateTime(),nullable=False)
    duration = db.Column(db.String(120),nullable=False)
    submitedDate = db.Column(db.Date(),nullable=False)
    approval = db.Column(db.Boolean, nullable=False)
    note = db.Column(db.Text, nullable=False)
    orgName = db.Column(db.String(120), nullable=False)
    shiftName = db.Column(db.String(150))
    orgName = db.Column(db.String(120), nullable=False)
    shiftName = db.Column(db.String(150))


    def __repr__(self):
        return '<timeCard %r>' % self.whoName+","+str(self.submitedDate)


class clockedIn (db.Model):
    __tablename__ = 'clockedIn'
    id = db.Column(db.String(150), primary_key=True)

    who = db.Column(db.BigInteger(), db.ForeignKey('Users.id'),nullable=False)
    start = db.Column(db.DateTime(),nullable=False)
    orgName = db.Column(db.String(120), nullable=False)
    orgName = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return '<clockedIn %r>' % self.who+","+self.start
    
    

class shifts(db.Model):
    __tablename__ = 'shifts'
    id = db.Column(db.String(150), primary_key=True)
    shiftName = db.Column(db.String(150))
    orgName = db.Column(db.String(150))

    def __repr__(self):
        return '<shifts %r>' % self.orgName+","+self.shiftName





def addShiftsIn(_shifts):
    print("********************************")
    print("Checking Shifts...")
    count = 0
    for shift in _shifts:
        curShift = shifts.query.filter_by(orgName = shift[0], shiftName= shift[1]).first()
        if curShift is None:
            count +=1
            print(shift[1]," - Not found! \n Adding...")
            newShift = shifts(
                id=str(uuid.uuid4()),
                shiftName= shift[1],
                orgName= shift[0],
            )
            db.session.add(newShift)
            db.session.commit()
    if count == 0: 
        print("All shifts already exists!")
    else:
        print("All shifts added!")
    print("\n")

def addOrgsIn(_orgs):
    print("********************************")
    print("Checking Orgs...")
    count = 0
    for org in _orgs:
        curOrg = organizations.query.filter_by(OrgName=org).first()
        if curOrg is None:
            count +=1
            print(org," - Not found! \n Adding...")
            newOrg = organizations(
                id=str(uuid.uuid4()),
                OrgName=org,
            )
            db.session.add(newOrg)
            db.session.commit()
    if count == 0: 
        print("All Orgs already exists!")
    else:
        print("All Orgs added!")
    print("\n")

def addFeaturesIn(_features):
    print("********************************")
    print("Checking all Features...")
    count = 0
    for feature in _features:
        curFeature = features.query.filter_by(featureName=feature[2] , org=feature[0] ).first()
        if curFeature is None:
            count +=1
            print(feature[2]," for ",feature[0] ," - Not found! \n Adding...")
            temp =False
            if feature[3] != "" or feature[4] =="":
                temp = True
            newFeature = features(
                id=str(uuid.uuid4()),
                org=feature[0],
                featureName= feature[2],
                dashboardFeature = feature[5],
                internallyManaged = temp,
                internalUrl=feature[3], 
                externalUrl=feature[4],
                permissionManagement = feature[6],
            )
            db.session.add(newFeature)
            db.session.commit()
    if count == 0: 
        print("All Features already exists!")
    else:
        print("All Features added!")
    print("\n")

def addPosIn(_pos):
    print("********************************")
    print("Checking all Positions...")
    count = 0
    for pos in _pos:
        curPos = orgNpos.query.filter_by(OrgName = pos[0], PosName=pos[1],  title = pos[2]).first()
        if curPos is None:
            count +=1
            print(pos[1]," in ",pos[0] ," - Not found! \n Adding...")
            newOrgNpos = orgNpos(
                id=str(uuid.uuid4()),
                OrgName=pos[0],
                PosName= pos[1],
                title = pos[2],
                availableNoPos = -1,
                # Org_hierarchyLevel=pos[3],
            )
            db.session.add(newOrgNpos)
            db.session.commit()
    if count == 0: 
        print("All Positions already exists!")
    else:
        print("All Positions added!")
    print("\n")

def addFeaturePermissionToPosIn(fets,oNps):
    print("********************************")
    print("Checking all permisions...")
    count =0
    for feature in fets:
        curFeature = features.query.filter_by(featureName=feature[2], org=feature[0]).first()
        for op in oNps:
            if op[0] == feature[0]:
                curPos =orgNpos.query.filter_by(OrgName = op[0], PosName=op[1],  title = op[2]).first()
                curPerm = featuresPermissions.query.filter_by(ownerID =curPos.id , featureId=curFeature.id ).first()
                if curPerm is None:
                    print(curFeature.featureName,",",curFeature.org," - not found for ",curPos.PosName,",",curPos.OrgName,"\n Adding...")
                    count+=1
                    newPerm = featuresPermissions(id =str(uuid.uuid4()),
                                                            featureId = str(curFeature.id),
                                                            view = (op[0] ==feature[0]) and (op[3]>=feature[1]) ,
                                                            create = (op[0] ==feature[0]) and (op[3]>=feature[1]),
                                                            edit = (op[0] ==feature[0]) and (op[3]>=feature[1]),
                                                            delete = (op[0] ==feature[0]) and (op[3]>=feature[1]),
                                                            blackListed =False,
                                                            ownerID = curPos.id,
                                                            userPerm = False,
                                                            featureName = feature[2],
                                                            who = op[0]+" "+op[1]+","+feature[2]+" "+feature[0]  )
                    curPos.featurePermissions.append(newPerm)
                    db.session.add(newPerm)
                    db.session.commit()
    if count == 0: 
        print("All permissions already exists!")
    else:
        print("All permissions added!")
    print("\n")


def createAdminIn():
    with db.session.no_autoflush:
        print("********************************")
        print("Checking all admin accounts...")
        count = 0
        orgs= organizations.query.all()
        for org in orgs:
            users= Users.query.all()
            count1 =0
            for user in users:
                temp = user.orgNpos
                for oNp in temp:
                    if oNp.OrgName == org.OrgName  and oNp.PosName == "admin" :
                        count1 += 1
            if count1 == 0 :
                count+=1
                print("No admin account found for ",org.OrgName,"\n Adding...")
                organization =org.OrgName
                oNp = orgNpos.query.filter_by(OrgName = organization,PosName ="admin").first()
                new_user = Users(
                    # id=str(uuid.uuid4()),
                    email="admin"+organization,
                    # passwordHash = generate_password_hash("admin", method='sha256'),
                    firstName = "admin",
                    lastName = str(organization),
                    collegeId = 0,
                    dob = str(datetime.date.today().strftime("%Y-%m-%d")),
                    )
                
                for permission in oNp.featurePermissions:
                    feature = features.query.get(permission.featureId)
                    ONP_newPermission = featuresPermissions(id =str(uuid.uuid4()),
                                                            featureId = str(feature.id),
                                                            view = permission.view ,
                                                            create =permission.create,
                                                            edit = permission.edit,
                                                            delete = permission.delete,
                                                            blackListed =permission.blackListed,
                                                            ownerID = new_user.id,
                                                            userPerm = True,
                                                            featureName = permission.featureName,
                                                            who = new_user.firstName+" "+new_user.lastName+","+permission.featureName
                                                            )
                    db.session.add(ONP_newPermission)
                    new_user.featurePermissions.append(ONP_newPermission)
                new_user.orgNpos.append(oNp)
                db.session.add(new_user) 
                db.session.commit()
        if count == 0: 
            print("An admin account for all orgs exists!")
        else:
            print("Admin accounts updated!")
        print("\n")

def updatePermissionsIn():
    print("********************************")
    print("Checking all admin accounts...")
    count = 0
    users = Users.query.all()
    for user in users:
        for oNp in user.orgNpos:
            for permission in oNp.featurePermissions:
                userPerm = featuresPermissions.query.filter_by(featureId = permission.featureId, ownerID = user.id).first()
                if userPerm is None:
                    count +=1
                    print(permission.featureName," - not found for ",user.lastName, ",",user.firstName)
                    ONP_newPermission = featuresPermissions(id =str(uuid.uuid4()),
                                                        featureId = str(permission.featureId),
                                                        view = permission.view ,
                                                        create =permission.create,
                                                        edit = permission.edit,
                                                        delete = permission.delete,
                                                        blackListed =permission.blackListed,
                                                        ownerID = user.id,
                                                        userPerm = True,
                                                        featureName = permission.featureName,
                                                        who = user.firstName+" "+user.lastName+","+permission.featureName
                                                        )
                    db.session.add(ONP_newPermission)
                    user.featurePermissions.append(ONP_newPermission)
                    db.session.commit()
    if count == 0: 
        print("All account permissions already exists!")
    else:
        print("All permissions updated!")
    print("\n")

def deleteFeatureNpermissionIn(_features):
    print("********************************")
    print("Checking features to be deleted...")
    count = 0
    for feature in _features:
        curFeature = features.query.filter_by(featureName = feature[0], org = feature[1]).first()
        if curFeature is None:
            print(feature[0]," of ", feature[1], " is to be deleted but not found!")
        else:
            count = count+1
            print(feature[0]," of ", feature[1],"deleting...")
            permissions = featuresPermissions.query.filter_by(featureId = curFeature.id).all()
            for permission in permissions:
                db.session.delete(permission)
            db.session.delete(curFeature)
            db.session.commit()
    if count ==0:
        print("No features deleted!")
    else:
        print("Following features deleted:")
        print(_features)
    print("\n")



def setPromotionsRelationsIn(promotions):
    with db.session.no_autoflush:
        print("********************************")
        print("Checking all promotion and demotions relations...")
        for pos in promotions:
            curPos = orgNpos.query.filter_by(OrgName = pos[0], PosName=pos[1],  title = pos[2]).first()
            curPromotion = promoteTo.query.filter_by(promoteFrom = curPos.id).first()
            if curPromotion == None:
                newpromotion = promoteTo(
                    id =str(uuid.uuid4()),
                    promoteFrom = curPos.id,
                )
                
                for proTo in pos[3]:
                    nextPos = orgNpos.query.filter_by(OrgName = proTo[0], PosName=proTo[1],  title = proTo[2]).first()
                    newpromotion.nextPos.append(nextPos)

                db.session.add(newpromotion)
                db.session.commit()
                

def setDeomotionsRelationsIn(promotions):

    print("********************************")
    print("Checking all demotion and demotions relations...")
    for pos in promotions:
        nextPos = orgNpos.query.filter_by(OrgName = pos[0], PosName=pos[1],  title = pos[2]).first()
        for proTo in pos[3]:
            curPos = orgNpos.query.filter_by(OrgName = proTo[0], PosName=proTo[1],  title = proTo[2]).first()
            curDemotion = demoteTo.query.filter_by(demoteFrom = curPos.id).first()

            if curDemotion == None:
                newDemotion = demoteTo(
                    id =str(uuid.uuid4()),
                    demoteFrom = curPos.id,
                )
                newDemotion.nextPos.append(nextPos)
                db.session.add(newDemotion)
                
            else:
                curDemotion.nextPos.append(nextPos)
            db.session.commit()

def createDevAdmin(orgs):
    users= Users.query.all()
    found =False
    print("Finding DEV_OP...")
    for user in users:
        if user.email == "dev@ithaca.edu":
            found = True
    if found:
        print("DEV_OP found!")
        return
    print("DEV_OP not found, making one...")
    new_user = Users(
                    # id=str(uuid.uuid4()),
                    email="dev@ithaca.edu",
                    # passwordHash = generate_password_hash("admin", method='sha256'),
                    firstName = "DEV_OP",
                    lastName = "admin",
                    collegeId = 0,
                    dob = str(datetime.date.today().strftime("%Y-%m-%d")),
                    )
    oNp = orgNpos.query.filter_by(OrgName = "DevOps",PosName ="admin").first()
    new_user.orgNpos.append(oNp)
    db.session.add(new_user) 
    for org in orgs:
        oNp = orgNpos.query.filter_by(OrgName = org ,PosName ="admin").first()
        new_user.orgNpos.append(oNp)
        for permission in oNp.featurePermissions:
                    feature = features.query.get(permission.featureId)
                    ONP_newPermission = featuresPermissions(
                                                            id =str(uuid.uuid4()),
                                                            featureId = str(feature.id),
                                                            view = permission.view ,
                                                            create =permission.create,
                                                            edit = permission.edit,
                                                            delete = permission.delete,
                                                            blackListed =permission.blackListed,
                                                            ownerID = new_user.id,
                                                            userPerm = True,
                                                            featureName = permission.featureName,
                                                            who = new_user.firstName+" "+new_user.lastName+","+permission.featureName
                                                            )
                    db.session.add(ONP_newPermission)
                    new_user.featurePermissions.append(ONP_newPermission)
    
    db.session.commit()
    print("DEV_OP made!")
    



 

# dataBase data init
# please be carefull while editing this code as it can affect the whole database
def adminINIT():

    orgs = [
        "SASP",
        "RESLIFE",
        "Parkings",
        "DevOps",
    ]
    oNp=[
        ["SASP","Probationary Member","Probationary Member",0],
        ["SASP","Junior Member","Junior Member",1],
        ["SASP","Senior Member","Senior Member",2],
        ["SASP","Executive Board Member","Executive Director",3],
        ["SASP","Executive Board Member","Operations Coordinator",3],
        ["SASP","Executive Board Member","Communications Coordinator",3],
        ["SASP","Executive Board Member","Training Coordinator",3],

        ["SASP","admin","admin",4],

        ["RESLIFE","RA","RA",0],
        ["RESLIFE","Senior RA","Senior RA",1],
        ["RESLIFE","admin","admin",2],

        ["Parkings","probi","probi",0],
        ["Parkings","emp","emp",1],
        ["Parkings","admin","admin",2],
        
        ["DevOps","admin","admin",5],
        ["DevOps","Senior","Senior",1],
        ["DevOps","Junior","Junior",0],
        ]
    
    promotions=[
        ["SASP","Probationary Member","Probationary Member",[["SASP","Junior Member","Junior Member",1]]],
        ["SASP","Junior Member","Junior Member",[["SASP","Senior Member","Senior Member",2],]],
        ["SASP","Senior Member","Senior Member",
         [["SASP","Executive Board Member","Executive Director",3],
          ["SASP","Executive Board Member","Operations Coordinator",3],
          ["SASP","Executive Board Member","Training Coordinator",3],
          ["SASP","Executive Board Member","Communications Coordinator",3],
          ["SASP","admin","admin",4],
          ]],
        ["SASP","Executive Board Member","Executive Director",[["SASP","admin","admin",4],]],
        ["SASP","Executive Board Member","Operations Coordinator",[["SASP","admin","admin",4],]],
        ["SASP","Executive Board Member","Communications Coordinator",[["SASP","admin","admin",4],]],
        ["SASP","Executive Board Member","Training Coordinator",[["SASP","admin","admin",4],]],
        ["SASP","admin","admin",[]],

        ["RESLIFE","RA","RA",[["RESLIFE","Senior RA","Senior RA",1]]],
        ["RESLIFE","Senior RA","Senior RA",[["RESLIFE","admin","admin",2]]],
        ["RESLIFE","admin","admin",[]],

        ["Parkings","probi","probi",[["Parkings","emp","emp",1]]],
        ["Parkings","emp","emp",[]],
        ["Parkings","admin","admin",[["Parkings","admin","admin",2]]],
        
        ["DevOps","admin","admin",[]],
    ]

    Fets=[


    # Format: ORG, hierarchy level, Feature name, internal url, external url, Dashboard feature, Permission Management
    # Note: 
    #   -It is either internal or external url, Not Both!!
    #   -Dashboard feature is a bool and required to be true for features with internal/external url
    #   -Permission management is a bool, which if true allows admin to controll user permission to the feature
    # sasp featuers
    ["SASP",0,"Daily","/SASPpages/daily","" ,True,False],
    ["SASP",0,"Records","/SASPpages/Records", "",True,True],
    ["SASP",0,"Referrals","/SASPpages/referrals","",True ,True],
    ["SASP",0,"Time Cards","/time-cards","",True,True],
    ["SASP",4,"Incidents","/SASPpages/incidents","",True,True],
    ["SASP",4,"Locations","/SASPpages/locations","",True,True],
    ["SASP",3,"Employee Accounts","/employee-accounts","",True,True],
    ["SASP",4,"All Time Cards","","",False,True],
    ["SASP",0,"Status","","",False,False],
    ["SASP",4,"Shifts","/shifts","",True,True],
    ["SASP",4,"Disciplinary Actions","/disciplinaryActions","",True,True],
    ["SASP",4,"Disciplinary Records","/disciplinaryRecords","",True,True],
    ["SASP",4,"Links","/links","",True,True],
    ["SASP",4,"Position","/positions","",True,True],

    ["RESLIFE",0,"Time Cards","/time-cards","",True,True],
    ["RESLIFE",2,"Employee Accounts","/employee-accounts","",True,True],
    ["RESLIFE",2,"All Time Cards","","",False,True],
    ["RESLIFE",2,"Status","","",False,False],
    ["RESLIFE",2,"Shifts","/shifts","",True,True],
    ["RESLIFE",2,"Links","/links","",True,True],
    ["RESLIFE",2,"Position","/positions","",True,True],

    # parkings features
    ["Parkings",0,"Time Cards","/time-cards","",True,True],
    ["Parkings",2,"Employee Accounts","/employee-accounts","",True,True],
    ["Parkings",2,"All Time Cards","","",False,True],
    ["Parkings",2,"Status","","",False,False],
    ["Parkings",2,"Shifts","/shifts","",True,True],
    ["Parkings",2,"Links","/links","",True,True],
    ["Parkings",2,"Position","/positions","",True,True],
    

    # devops features
    ["DevOps",0,"Employee Accounts","/employee-accounts","",True,True],
    ["DevOps",0,"Status","","",False,False],
    ]

    _shifts =[
        ["SASP","Late Patrol"],
        ["SASP","Special"],
        ["SASP","Other"],
    ]

    deletedFeature =[]
    allFeatures = features.query.all()

    for feature in allFeatures:
        count = 0
        for fet in Fets:
            if feature.featureName == fet[2] and feature.org == fet[0] and feature.externalUrl=="":
                count += 1
        if count == 0:
            deletedFeature.append([feature.featureName,feature.org])


    addShiftsIn(_shifts)
    addOrgsIn(orgs)
    addFeaturesIn(Fets)
    addPosIn(oNp)
    addFeaturePermissionToPosIn(Fets,oNp)
    createAdminIn()
    createDevAdmin(orgs)
    updatePermissionsIn()
    # deleteFeatureNpermissionIn(deletedFeature)
    setPromotionsRelationsIn(promotions)
    setDeomotionsRelationsIn(promotions)
    
db.create_all()
adminINIT()
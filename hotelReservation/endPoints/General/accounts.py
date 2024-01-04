from loguru import logger
from hotelReservation import app, db
import uuid
import json
from ... import models
from ...utils import token as tk
from ...utils import token as tk
from werkzeug.security import generate_password_hash,check_password_hash
from flask import Flask, jsonify, make_response, request



@app.route("/")
def healthcheck():
    return {"healthcheck": None}




@app.route('/register', methods=['POST'])
@logger.catch()
def signup_user(): 

   
    data = json.loads(request.data)
    accs = models.Users.query.all()
    # token = tk.validateTk(data["token"]) 

    # if token == "":
    #     return jsonify({'message': 'Invalid or expired token!'}),400

    # check if the account with this email already exists

    new_user = models.Users(

        email = data['email'],
        passwordHash = str(data['password']),
        firstName = str(data['firstName']),
        lastName = str(data['lastName']),
        )
    

    db.session.add(new_user) 
    db.session.commit()   
    return jsonify({'message': 'registered successfully'}), 200

@app.route('/checkAccount', methods=['POST'])
def checkAccount(): 

    data = json.loads(request.data)
    acc = models.Users.query.filter_by(email=data["email"]).first() 
    print(acc != None)
    if acc != None:
        UserAcc = {
            "id": acc.id,
            "email": acc.email,
            "firstName": acc.firstName,
            "lastName": acc.lastName,
            "collegeId": acc.collegeId,
            "dob": acc.dob,

            # "orgNpos": acc.orgNpos,

        }

        return jsonify({'accountFound':True, "UserAcc":UserAcc,'status': 200})
    else:
        return jsonify({'accountFound':False, 'status': 200})



@app.route('/editAccountDetails', methods=['POST'])
def editAccount(): 

    data = json.loads(request.data)

    token = tk.validateTk(data["token"]) 
    if token == "":
        return jsonify({'message': 'Invalid or expired token!',"status":400})
    authUser = models.Users.query.get(token["user_id"])
    authUserOrg = data["org"]

    authUserPermission = fNp.getPermisionIn(authUser.id,authUserOrg, "Employee Accounts")

    acc = models.Users.query.get(data["userID"])
    accOrgs = []
    for orgs in acc.orgNpos:
        accOrgs.append(orgs.OrgName)

    if (acc.id == authUser.id) or ((authUserOrg in accOrgs) and authUserPermission.edit and (not authUserPermission.blackListed) ) :
        
        
        acc.email = data["email"]
        acc.firstName = data["firstName"]
        acc.lastName = data["lastName"]
        acc.dob = data["dob"]
        acc.collegeId = data["collegeId"]
        db.session.commit() 
        return jsonify({'message': "Account details updated successfully!" ,"status":200})

    return jsonify({'message': "Not Authorized to perform this action!" ,"status":400}) 




@app.route('/login', methods=['POST']) 
def login_user():

    auth = json.loads(request.data)

    if  auth["email"] =="": 
        return make_response('could not verify', 401, {'Authentication': 'login required"'})   
    
    user = models.Users.query.filter_by(email=auth["email"]).first() 
    if user== None:
        return jsonify({"Response": "No User Found"}), 400

    generalStat= False

    for onp in user.orgNpos:
        # Checks if the all the feature permission of an orgNpos are assigned to the user or not and if not assigns them
        # print(onp.OrgName)
        allFnp_Not_found = False
        for Cur_fNp in onp.featurePermissions:
            curUser_fNp = models.featuresPermissions.query.filter_by(ownerID = user.id,featureId = Cur_fNp.featureId).first()
            if curUser_fNp == None:
                allFnp_Not_found = True

        if allFnp_Not_found:
            # print("perms not found!")
            fNp.addPermissionsIn(onp, user)


        # Check if the account is active in any organization 
        perm = models.features.query.filter_by(featureName = "Status",org=onp.OrgName).first()
        for i in user.featurePermissions:
            
            if i.featureId == perm.id:
                generalStat = not i.blackListed


    if generalStat:
        token = tk.createTk(user.id, user.firstName, user.lastName, user.email)
        return jsonify({"token": token}), 200
    else:
        return jsonify({'message': 'Your account has been deactivated!'}), 401






@app.route('/getAccounts', methods=['GET'])
def getAccounts():

    token = request.args.get("token")
    userCurOrg = request.args.get("org")
    data = tk.validateTk(token) 


    if data == "":
        return jsonify({'message': 'Invalid or expired token!',"status": 400})

    authUser = models.Users.query.get(data["user_id"])
    userPermisions = authUser.featurePermissions
    
    temp = 0
    for perms in userPermisions:
        permT = models.features.query.get(perms.featureId)

        if permT.featureName == "Employee Accounts" and permT.org == userCurOrg:
            temp += 1
            if perms.blackListed or not(perms.view):
                return jsonify({'Message': "Not Authorized to access this information!"}),401
    if temp == 0 and not (authUser.email == "dev@ithaca.edu" and app.debug):
        return jsonify({'Message': "Not Authorized to access this information!"}),401
    
    allAcc = models.Users.query.all()

    # filter query
    id = request.args.get("accID")
    if id != "" and id !=None :
        allAcc = list(filter(lambda acc: acc.id == id, allAcc))
        if len(allAcc) == 0:
            return jsonify({'message': "Account not found!"}), 404
        UserAcc = {
                    "id": allAcc[0].id,
                    "email": allAcc[0].email,
                    "firstName": allAcc[0].firstName,
                    "lastName": allAcc[0].lastName,
                    "collegeId": allAcc[0].collegeId,
                    "dob": allAcc[0].dob,}
        orgs=[]
        for orgNpos in allAcc[0].orgNpos:
            orgs.append({
                "org":orgNpos.OrgName,
                "pos":orgNpos.PosName,
                "title": orgNpos.title,
            })
        
        tempFNP = fNp.getFeaturePermissionsIN(id)
        featuresNpermisions = []
        if authUser.id != id:
            for fnp in tempFNP:
                feature = models.features.query.get(fnp["featureId"])
                if userCurOrg == feature.org :
                    featuresNpermisions.append(fnp)
        else:
            featuresNpermisions = tempFNP
        return jsonify({'accountDetails': UserAcc,"orgNpos":orgs,"featureNpermisions":featuresNpermisions}), 200

    email = request.args.get("email")
    if email != "" and email !=None :
        allAcc = list(filter(lambda acc: acc.email == email, allAcc))
    
    firstName = request.args.get("firstName")
    if firstName != "" and firstName !=None :
        allAcc = list(filter(lambda acc: acc.firstName == firstName, allAcc))
    
    lastName = request.args.get("lastName")
    if lastName != "" and lastName !=None :
        allAcc = list(filter(lambda acc: acc.lastName == lastName, allAcc))
    
    status = request.args.get("status")
    statusB = ""
    if status == "Active":
        statusB = True
    if status == "Deactivated":
        statusB = False

    if statusB != "" :
        allAcc = list(filter(lambda acc: acc.status == statusB, allAcc))

    ICID = request.args.get("ICID")
    if ICID != "" and ICID !=None :
        allAcc = list(filter(lambda acc: str(acc.collegeId) == ICID, allAcc))

    accounts = []

    for acc in allAcc:
        
        orgNpos = acc.orgNpos
        for oNp in orgNpos:
            print(oNp.OrgName )
            print(userCurOrg)
            if oNp.OrgName == userCurOrg:
                print(acc)
                perm = models.features.query.filter_by(featureName = "Status",org=userCurOrg).first()
                userAcc = acc
                curOrgAccStats = ""
                for i in userAcc.featurePermissions:
                    if i.featureId == perm.id:
                        curOrgAccStats = i 
                UserAcc = {
                        "id": acc.id,
                        "email": acc.email,
                        "firstName": acc.firstName,
                        "lastName": acc.lastName,
                        "collegeId": acc.collegeId,
                        "dob": acc.dob,
                        'status':not curOrgAccStats.blackListed,
                        "position": oNp.PosName,}
                accounts.append(UserAcc)
                




    return jsonify({'accounts': accounts}),200




@app.route("/deleteAccount", methods=["POST"])
def deleteAccount():
    data = json.loads(request.data)

    token = tk.validateTk(data["token"]) 

    if token == "":
        return jsonify({'message': 'Invalid or expired token!'})
    authUser = models.Users.query.get(token["user_id"])
    acc = models.Users.query.get(data["userID"])

    if authUser == None:
        return jsonify({'message': 'Your account is curenlty not accessible! Try again or contact admin.'}),500 
    if acc == None:
        return jsonify({'message': 'Account to delete not Found!'}), 404
    if acc == authUser:
        return jsonify({'message': 'Can not delete currently logged in account!'}), 405   

    for permission in authUser.featurePermissions :
        if permission.featureName == "Employee Accounts":
            if permission.delete and (not permission.blackListed) :

                permissions = models.featuresPermissions.query.filter_by(ownerID = acc.id)
                for permission in permissions:
                    db.session.delete(permission)

                db.session.delete(acc)
                db.session.commit()
                return jsonify({"message":"Account deleted successfully!" }),200

    
    return jsonify({"message":"Not Authorized to perform this action!" }),401


@app.route("/changeAccountStatus", methods=["POST"])
def changeAccountStatus():
    data = json.loads(request.data)
    userCurOrg = data["org"]
    token = tk.validateTk(data["token"]) 

    if token == "":
        return jsonify({'message': 'Invalid or expired token!'})

    authUserPerms = fNp.getPermisionIn(token["user_id"],userCurOrg,"Employee Accounts")
    if not authUserPerms:
        return jsonify({"message":"Not Authorized to perform this action!","status":400 })

    acc = models.Users.query.get(data["userID"])
    if acc != None:
        if authUserPerms.edit and  not authUserPerms.blackListed :
            perm = models.features.query.filter_by(featureName = "Status", org=userCurOrg).first()
            userAcc = acc
            curOrgAccStats = ""
            for i in userAcc.featurePermissions:
                if i.featureId == perm.id:
                    curOrgAccStats = i 
            temp = ""
            if curOrgAccStats.blackListed:
                curOrgAccStats.blackListed = False
                temp = "Activated"
            else:
                curOrgAccStats.blackListed = True
                temp = "Deactivated"
            db.session.commit()
            return jsonify({"message":"Account "+temp+"  successfully!" ,"status":200})
    else:
        return jsonify({"message":"Account not found!","status":400 })

    
    return jsonify({"message":"Not Authorized to perform this action!","status":400 })





'''
data{
    accountID
}
'''
@app.route("/getAccountDetails", methods=["GET"])
def getAccountDetails():
    token = tk.validateTk(request.args.get('token'))

    if token == "":
        return jsonify({'message': 'Invalid or expired token!',"status": 400})
    authUser = models.Users.query.get(token["user_id"])
    UserAcc = {
                    "id": authUser.id,
                    "email": authUser.email,
                    "firstName": authUser.firstName,
                    "lastName": authUser.lastName,
                    "collegeId": authUser.collegeId,
                    "dob": authUser.dob,}
    orgs=[]
    for orgNpos in authUser.orgNpos:
        orgs.append({
            "org":orgNpos.OrgName,
            "pos":orgNpos.PosName,
            "title": orgNpos.title,
        })
    
    tempFNP = fNp.getFeaturePermissionsIN(token["user_id"])
    featuresNpermisions = []
    featuresNpermisions = tempFNP
    return jsonify({'accountDetails': UserAcc,"orgNpos":orgs,"featureNpermisions":featuresNpermisions,"status": 200})




@app.route("/validate-token", methods=["POST"])
def validate_user_token():

    try:
        token = json.loads(request.data)["token"]
    except:
        return {"message": "failed"}, 400
        
    userInfo = tk.validateTk(token)
    if userInfo != "":
        return {"message": "verified", "user": userInfo}, 200

    return {"message": "failed"}, 400
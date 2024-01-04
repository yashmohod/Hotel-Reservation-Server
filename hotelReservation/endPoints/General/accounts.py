from anzen import app, db
import uuid
import json
from ... import models
from ...utils import token as tk
from ...utils import token as tk
from werkzeug.security import generate_password_hash,check_password_hash
from flask import Flask, jsonify, make_response, request
from . import features_permissions as fNp
from loguru import logger

@app.route("/")
def healthcheck():
    """
    Healthcheck endpoint

    Check if the application is running.
    ---
    responses:
        200:
            description: Success
            content:
                application/json:
                    schema:
                    type: object
                    properties:
                        status:
                        type: string
                        description: The status of the application
                        message:
                        type: string
                        description: A message indicating the application is running
        500:
            description: Internal Server Error
            content:
                application/json:
                    schema:
                        type: object
                        properties:
                            status:
                            type: string
                            description: The status of the application
                            message:
                            type: string
                            description: A message indicating the application is running

    """
    return {"healthcheck": None}




@app.route('/register', methods=['POST'])
@logger.catch()
def signup_user(): 
    """
    Signup endpoint

    Signup new user to the application
    ---
    parameters:
     - in: body
       name: body
       description: Information needed to signup the new user
       required: true
       schema:
            type: object
            properties:
                email:
                    type: string
                    required: true
                password:
                    type: string
                    required: true
                firstName:
                    type: string
                    required: true
                lastName:
                    type: string
                    required: true
                collegeId:
                    type: integer
                    required: true
                dob:
                    type: string
                    required: true
                organization:
                    type: string
                    required: true
                position:
                    type: string
                    required: true
    responses:
        200:
            description: Success
            content:
                application/json:
                    schema:
                    type: object
        500:
            description: Internal Server Error
            content:
                application/json:
                    schema:
                        type: object
    """
   
    """
    Signup endpoint

    Signup new user to the application
    ---
    parameters:
     - in: body
       name: body
       description: Information needed to signup the new user
       required: true
       schema:
            type: object
            properties:
                email:
                    type: string
                    required: true
                password:
                    type: string
                    required: true
                firstName:
                    type: string
                    required: true
                lastName:
                    type: string
                    required: true
                collegeId:
                    type: integer
                    required: true
                dob:
                    type: string
                    required: true
                organization:
                    type: string
                    required: true
                position:
                    type: string
                    required: true
    responses:
        200:
            description: Success
            content:
                application/json:
                    schema:
                    type: object
        500:
            description: Internal Server Error
            content:
                application/json:
                    schema:
                        type: object
    """
   
    data = json.loads(request.data)
    accs = models.Users.query.all()
    token = tk.validateTk(data["token"]) 
    # authUser = models.Users.query.get(token["user_id"])

    if token == "":
        return jsonify({'message': 'Invalid or expired token!'}),400
    
    oNp = models.orgNpos.query.get(data["orgNpos"])
    if oNp == None:
        return jsonify({'message': 'Error Occurred' }), 500
        return jsonify({'message': 'Invalid or expired token!'}),400
    
    oNp = models.orgNpos.query.get(data["orgNpos"])
    if oNp == None:
        return jsonify({'message': 'Error Occurred' }), 500

    # check if the account with this email already exists
    for acc in accs:
        if acc.email == data["email"]:
            exsistingUser = models.Users.query.filter_by(email=data["email"]).first()
            exsistingUser.firstName = str(data['firstName'])
            exsistingUser.lastName = str(data['lastName'])
            exsistingUser.collegeId = int(data['collegeId'])
            exsistingUser.dob = str(data['dob'])
            exsistingUser.orgNpos.append(oNp)
            


            # update or add new permissions 
            fNp.updatePermissionsIn(oNp,acc)
            
            return jsonify({'message': 'Account add to org!'}),200


        if acc.email == data["email"]:
            exsistingUser = models.Users.query.filter_by(email=data["email"]).first()
            exsistingUser.firstName = str(data['firstName'])
            exsistingUser.lastName = str(data['lastName'])
            exsistingUser.collegeId = int(data['collegeId'])
            exsistingUser.dob = str(data['dob'])
            exsistingUser.orgNpos.append(oNp)
            


            # update or add new permissions 
            fNp.updatePermissionsIn(oNp,acc)
            
            return jsonify({'message': 'Account add to org!'}),200



    # hashed_password = generate_password_hash(data['password'], method='sha256')            
    # hashed_password = generate_password_hash(data['password'], method='sha256')            
    new_user = models.Users(
        # id=str(uuid.uuid4()),
        # userName=str(data['userName']),
        email = data['email'],
        # passwordHash = str(hashed_password),
        # passwordHash = str(hashed_password),
        firstName = str(data['firstName']),
        lastName = str(data['lastName']),
        collegeId = int(data['collegeId']),
        dob = str(data['dob']),


        )
    
    fNp.addPermissionsIn(oNp, new_user)

    new_user.orgNpos.append(oNp)
    
    fNp.addPermissionsIn(oNp, new_user)

    new_user.orgNpos.append(oNp)
    db.session.add(new_user) 
    db.session.commit()   
    return jsonify({'message': 'registered successfully'}), 200

@app.route('/checkAccount', methods=['POST'])
def checkAccount(): 
    """
    Check Account endpoint

    Check if an account already exists and return the metadata
    ---
    parameters:
     - in: body
       name: body
       description: Information needed to signup the new user
       required: true
       schema:
            type: object
            properties:
                id:
                    type: string
                    required: true
                email:
                    type: string
                    required: true
                firstName:
                    type: string
                    required: true
                lastName:
                    type: string
                    required: true
                collegeId:
                    type: integer
                    required: true
                dob:
                    type: string
                    required: true
                status:
                    type: boolean
                    required: true

    responses:
        200:
            description: Success
            content:
                application/json:
                    schema:
                    type: object
        500:
            description: Internal Server Error
            content:
                application/json:
                    schema:
                        type: object
    """
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



'''
tested
data{
    token
    organization
    userID (of which to update details of)
    #account details:
    # update these details if the account owner is updating
    email
    firstName
    lastName
    dob
    # update these details as well if the admin account is updating
    status
    organization
    position
}
return{
    "invalid or expired token": for expired token or courrpt token
    "Account details updated successfully!": if the account details were updated
    "Not Authorized to perform this action!": if the user is not allowed to change the password for this account 
}
'''
@app.route('/editAccountDetails', methods=['POST'])
def editAccount(): 
    """
    Edit Account Details endpoint

    Edit the details of an account.
    ---
    parameters:
     -  in: body
        name: body
        required: true
        schema:
            type: object
            properties:
                token:
                    type: string
                    description: The token for authentication.
                org:
                    type: string
                    description: The organization of the authenticated user.
                userID:
                    type: integer
                    description: The ID of the user account to edit.
                email:
                    type: string
                    description: The updated email of the user account.
                firstName:
                    type: string
                    description: The updated first name of the user account.
                lastName:
                    type: string
                    description: The updated last name of the user account.
                dob:
                    type: string
                    description: The updated date of birth of the user account.
                collegeId:
                    type: string
                    description: The updated college ID of the user account.

    responses:
        200:
            description: Account details updated successfully.
            content:
                application/json:
                    schema:
                        type: object
                        properties:
                            message:
                                type: string
                                description: Success message.
                            status:
                                type: integer
                                description: HTTP status code.
        400:
            description: Not authorized to perform this action or invalid request.
            content:
                application/json:
                    schema:
                        type: object
                        properties:
                            message:
                                type: string
                                description: Error message.
                            status:
                                type: integer
                                description: HTTP status code.
"""
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


'''
data{
    token
    userId (of which to chenge password)
    password
}
return{
    "invalid or expired token": for expired token or courrpt token
    "Password updated successfully!": if the password was updated
    "Not Authorized to perform this action!": if the user is not allowed to change the password for this account 
}
'''
# @app.route('/editAccountPassword', methods=['POST'])
# def editAccountPassword():
#     """
#     Edit Account Password
#     ---
#     description: Edit the password of a user account.
#     tags:
#     - Account
#     parameters:
#      -  in: body
#         name: body
#         description: Request body for editing the account password.
#         required: true
#         schema:
#         type: object
#         properties:
#             token:
#                 type: string
#                 description: The token for authentication.
#             userID:
#                 type: integer
#                 description: The ID of the user account to edit.
#             password:
#                 type: string
#                 description: The new password for the account.
#     responses:
#         200:
#             description: Account password updated successfully.
#             content:
#             application/json:
#                 schema:
#                 type: object
#                 properties:
#                     message:
#                         type: string
#                         description: Success message.
#                     status:
#                         type: integer
#                         description: HTTP status code.
#         400:
#             description: Invalid or expired token or other error.
#             content:
#             application/json:
#                 schema:
#                 type: object
#                 properties:
#                     message:
#                         type: string
#                         description: Error message.
#                     status:
#                         type: integer
#                         description: HTTP status code.
# """
#     data = json.loads(request.data)

#     token = tk.validateTk(data["token"]) 
#     if token == "":
#         return jsonify({'message': 'Invalid or expired token!'}), 400
#     authUser = models.Users.query.get(token["user_id"])
        
#     acc = models.Users.query.get(data["userID"])

#     hashed_password = generate_password_hash(data['password'], method='sha256')
#     acc.passwordHash = hashed_password
#     db.session.commit() 

#     return jsonify({'message': "Password updated successfully!" , "status":200}), 200

#     # return jsonify({'message': "Not Authorized to perform this action!", "status":401}) 



@app.route('/login', methods=['POST']) 
def login_user():
    """
    Authenticate User
    ---
    description: Authenticate a user by validating their email and password.
    tags:
    - Authentication
    parameters:
    -   name: body
        in: body
        description: Request body for user authentication.
        required: true
        schema:
        type: object
        properties:
            email:
                type: string
                description: The user's email.
    responses:
        200:
            description: User authenticated successfully.
            content:
            application/json:
                schema:
                type: object
                properties:
                    token:
                        type: string
                        description: User authentication token.
    400:
        description: Invalid request or no user found.
        content:
        application/json:
            schema:
            type: object
            properties:
                Response:
                    type: string
                    description: Error response message.
    401:
        description: Authentication failed or login required.
        content:
        application/json:
            schema:
            type: object
            properties:
                Response:
                    type: string
                    description: Error response message.
"""
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





'''
tested
data{
    token
}
return{
    returns list of all the accounts of the selected organization 
}
'''
@app.route('/getAccounts', methods=['GET'])
def getAccounts():
    """
    Get Accounts
    ---
 
    responses:
        200:
            description: User accounts retrieved successfully.
            content:
            application/json:
                schema:
                type: object
    
        400:
            description: Invalid or expired token, account not found, or not authorized.
            content:
            application/json:
                schema:
                type: object
"""
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



'''
tested
data{
    token
    userId of account to be deleted
}
return{
    postion of the loged in user
}
'''
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

'''
tested
data{
    token
    userId of account to be deleted
}
return{
    
}
'''
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


# @app.route('/getPositions', methods=['GET'])
# def getPositions():
#     """
#     Get position endpoint
#     Get the position of the current user
#     ---
#     parameters:
#      -  in: query
#         name:  token
#         required: true
#         type: string
#      -  in: query
#         name:  org
#         required: true
#         type: string
#     responses:
#         200:
#             description: Success
#             content: 
#                 application/json:
#                     schema:
#                         type: object
#         400:
#             description: Bad request
#             content: 
#                 application/json:
#                     schema:
#                         type: object
#     """
    
#     token = request.args.get("token")
#     userCurOrg = request.args.get("org")
#     data = tk.validateTk(token) 
#     if data == "":
#         return jsonify({'message': 'Invalid or expired token!',"status": 400})

#     Poss = models.orgNpos.query.filter_by(OrgName = userCurOrg ).all()
#     poss =[]

#     for pos in Poss :
#         poss.append({
#             "id": pos.id,
#             "OrgName": pos.OrgName,
#             "PosName": pos.PosName,
#             "Org_hierarchyLevel": pos.Org_hierarchyLevel,
#         })


#     return jsonify({"positions":poss,"status":200})

'''
data{
    token
}
'''
@app.route("/validate-token", methods=["POST"])
def validate_user_token():
    """
    Validate token
    Validate the specified token and returns back the user information
    ---
    parameters:
    -   in: body
        name: body
        schema:
            type: object
            properties:
                token:
                    type: string
                    required: true
    responses:
        200:
            description: Success
            content:
                application/json:
                    schema:
                        type: object
        400:
            description: Bad request
            content:
                application/json:
                    schema:
                        type: object
    """
    try:
        token = json.loads(request.data)["token"]
    except:
        return {"message": "failed"}, 400
        
    userInfo = tk.validateTk(token)
    if userInfo != "":
        return {"message": "verified", "user": userInfo}, 200

    return {"message": "failed"}, 400
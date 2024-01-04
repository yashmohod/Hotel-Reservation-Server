import datetime
from anzen import app
from .. import models
import jwt

# creates token with encryption
def createTk(id, firstName, lastName, userName):
    token = jwt.encode(
        {'user_id' : id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45), 'firstName': firstName, 'lastName': lastName, 'userName': userName}
        , app.config['SECRET_KEY'], "HS256")
    return token

# validates the token:
#   First check if the token is assigned to a valid user
#   Second check if the token is not expired.
# if both are satisfactory then the function return true 
# if either condition is not met it returns false
def validateTk(token):
    decodedToken=None
    try:
        try:
            decodedToken = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            id = decodedToken["user_id"] 
            user = models.Users.query.get(id)
            if user == None:
                return ""
            else:
                return decodedToken

        except jwt.ExpiredSignatureError:
            # Signature has expired
            return ""
    except Exception as e: 
        print(e)
        return ""

    

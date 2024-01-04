import datetime
import pytz

"""
Date formate  Y-m-d H:M:S
Note : no accomodation for more that 24h yet please fix
"""
def formatDate(now):
    return datetime.datetime.strptime(now ,"%Y-%m-%d %H:%M:%S").replace(tzinfo=pytz.timezone('America/New_York')) 

"""
return currentDate
"""
def getNow():
    return datetime.datetime.now(pytz.timezone('America/New_York')).strftime("%Y-%m-%d %H:%M:%S")


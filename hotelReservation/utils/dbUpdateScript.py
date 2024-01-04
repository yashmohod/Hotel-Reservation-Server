
from sqlalchemy import create_engine
  
user, password, host, database = 'root', '123', 'localhost', 'geeksforgeeks'
engine = create_engine(
    url=f'mysql+pymysql://{user}:{password}@{host}/{database}?charset=utf8')
  
connection = engine.connect()

'''
 refer to this website to see how to alter tables :
 https://www.geeksforgeeks.org/python-sqlalchemy-update-table-structure/
'''


# edit the following and run to edit database

table_name = 'students'
query = f'ALTER TABLE {table_name} ADD gender ENUM("m","f") ;'
connection.execute(query)
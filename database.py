# Import the mysql.connector module, which allows Python to connect to and interact with a MySQL database.
import mysql.connector 
import os

# Establish a connection to the MySQL database by calling the connect() method.
# The connection is configured with the following parameters:
db = mysql.connector.connect(
    host=os.environ.get('DB_HOST', 'localhost'),  # The hostname where the MySQL server is running (in this case, localhost indicates the same machine)
    user=os.environ.get('DB_USER', 'root'),    # The username to log in to the MySQL server (commonly 'root' for a local development environment)
    password=os.environ.get('DB_PASSWORD', 'SaiKiran@2001'),  # The password associated with the MySQL user account
    database=os.environ.get('DB_NAME', 'ecommerce')  # The specific database to connect to (here, the 'ecommerce' database)
)

# Create a cursor object using the connection. 
# The cursor is used to execute SQL queries and fetch results from the database.
cursor = db.cursor()

# Import necessary functions and classes from Flask and other libraries
from flask import Flask, render_template, redirect, url_for, request, session, flash  # Import Flask core functions: Flask to create the app instance, render_template for HTML rendering, redirect and url_for for URL redirection, request for handling HTTP requests, session for user session management, and flash for temporary messaging.

# Flask-Mail is used for sending emails from our Flask app
from flask_mail import Mail, Message  # Import Mail for email configuration and Message to construct email messages

# itsdangerous is used to generate secure tokens for actions like password reset
from itsdangerous import URLSafeTimedSerializer, SignatureExpired  # Import URLSafeTimedSerializer for token generation/validation and SignatureExpired to handle expired tokens

# random module to generate random numbers (used for OTP generation)
import random  # Import Python's built-in random module to generate random numbers, e.g., for One-Time Password (OTP) creation

# Import the database connection (assumed to be set up in a separate module 'database')
from database import db  # Import the database object 'db' from the 'database' module which handles database connections and queries

# datetime and timedelta are used for time-related operations (e.g., calculating delivery dates)
from datetime import datetime, timedelta  # Import datetime for current date and time operations and timedelta for representing time differences (e.g., for order delivery estimations)

# Razorpay is used for payment processing
import razorpay  # Import the Razorpay module for handling payment gateway operations and interactions

# bcrypt is used for hashing passwords securely
import bcrypt  # Import bcrypt for hashing passwords, ensuring secure storage of user credentials

import os  # Import os module to interact with the operating system, e.g., reading environment variables

from decimal import Decimal  # Import Decimal from the decimal module for precise decimal arithmetic, useful in financial calculations

# (Optional) MySQL connector is commented out because we are using our own database module
# import mysql.connector  # This line is commented out; it would import the MySQL connector if using it directly instead of a custom database module

# Initialize the Flask application
app = Flask(__name__)  # Create a Flask application instance with the name of the current module

# Set the secret key for session management and security (used for signing cookies and tokens)
app.secret_key = os.environ.get("SECRET_KEY", "simplelogin")  # Retrieve the secret key from environment variables, defaulting to "simplelogin" if not set, used to secure sessions and token signatures

# Razorpay configuration: API key and secret for integrating Razorpay payment gateway
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "rzp_test_xxfkdUYWCKHS4E")      # Get the Razorpay Key ID from environment variables, with a fallback test key
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "DDFK36eIKqNL514rmiJ4vahF")   # Get the Razorpay Key Secret from environment variables, with a fallback test secret

# Create a Razorpay client instance using the provided API credentials
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))  # Initialize the Razorpay client with authentication using the API key and secret

# Configure Flask-Mail settings for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Set the mail server to Gmail's SMTP server
app.config['MAIL_PORT'] = 587  # Set the port for TLS encryption (commonly 587 for SMTP)
app.config['MAIL_USE_TLS'] = True  # Enable TLS encryption for secure email transmission
app.config['MAIL_USE_SSL'] = False  # Do not use SSL as TLS is already enabled
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME", "thadkapallysaikiran2001@gmail.com")  # Set the sender's email address from environment variable or default to the provided Gmail address
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD", "ktvq inal srse itjg")  # Set the email password from environment variable or default to the provided password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER", "thadkapallysaikiran2001@gmail.com")  # Set the default sender address for emails sent by the application

# Initialize Flask-Mail with the app configuration
mail = Mail(app)  # Create a Mail instance for the app using the configuration settings above

# Initialize a URLSafeTimedSerializer with the app's secret key for token generation (e.g., password reset)
s = URLSafeTimedSerializer(app.secret_key)  # Create a serializer that uses the secret key for securely signing tokens with expiration support

# Function to generate a 6-digit OTP as a string
def generate_otp():
    return str(random.randint(100000, 999999))  # Generate a random integer between 100000 and 999999, convert it to string to form a 6-digit OTP

# Function to send an OTP email using Flask-Mail
def send_otp_email(name, email, otp):
    try:
        # Create an email message with subject and recipient
        msg = Message('OTP for Verification', recipients=[email])  # Construct a Message object with subject "OTP for Verification" and recipient list containing the provided email
        # Set the body of the email with a personalized message including the OTP
        msg.body = f"Hello {name}!\nYour OTP is: {otp}"  # Set the email message body with a greeting and the OTP embedded in the text
        # Send the email
        mail.send(msg)  # Use the Mail instance to send the constructed email message
        return True  # Return True indicating that the email was sent successfully
    except Exception as e:
        # Print any error that occurs during email sending and return False
        print("Error sending email:", e)  # Log the error to the console for debugging purposes
        return False  # Return False indicating that there was an error sending the email

# Route for the dashboard (home page of the store)
@app.route('/')
def dashboard():
    # Create a cursor that returns results as dictionaries
    cursor = db.cursor(dictionary=True)  # Open a database cursor that returns query results as dictionaries for easy key access
    # Execute SQL query to fetch all products from the products table
    cursor.execute("SELECT * FROM products")  # Execute a SELECT query to retrieve all records from the 'products' table
    # Fetch all rows from the query result
    products = cursor.fetchall()  # Retrieve all product rows from the query result into a list
    # Render the dashboard template with the fetched products
    return render_template('dashboard.html', products=products)  # Render the 'dashboard.html' template, passing the list of products as a variable

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':  # Check if the request method is POST (form submission)
        # Retrieve user input from the form fields
        username = request.form.get('username')  # Get the 'username' field from the submitted form data
        email = request.form.get('email')  # Get the 'email' field from the submitted form data
        password = request.form.get('password')  # Get the 'password' field from the submitted form data
        # Hash the password using bcrypt for secure storage
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')  # Hash the password using bcrypt with a generated salt, and decode the hash to a UTF-8 string for storage
        
        # Insert new user into the users table
        cursor = db.cursor()  # Open a new database cursor for executing SQL queries
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))  # Execute an INSERT query to add the new user to the 'users' table with the provided username, email, and hashed password
        db.commit()  # Commit the transaction to save the changes to the database
        
        # After successful registration, redirect to the login page
        return redirect(url_for('login'))  # Redirect the user to the 'login' route after registration
    # For GET requests, simply render the registration page
    return render_template('register.html')  # Render the 'register.html' template for user registration

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Check if the login form has been submitted via POST
        # Retrieve email and password from the login form
        email = request.form.get('email')  # Get the 'email' input from the login form
        password = request.form.get('password')  # Get the 'password' input from the login form
        
        # Query the users table to fetch user details for the given email
        cursor = db.cursor()  # Open a new database cursor
        cursor.execute("SELECT id, username, password FROM users WHERE email=%s", (email,))  # Execute a SELECT query to find the user with the given email
        user = cursor.fetchone()  # Retrieve a single user record from the query result
        
        # Check if user exists and the password matches (using bcrypt for comparison)
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):  # Verify that the user exists and that the submitted password matches the stored hashed password using bcrypt
            # Set session variables for the logged-in user
            session['user_id'] = user[0]  # Store the user's ID in the session for tracking logged-in state
            session['username'] = user[1]  # Store the user's username in the session for personalization
            # Generate an OTP and store it in the session for verification
            otp = generate_otp()  # Generate a 6-digit OTP using the generate_otp() function
            session['otp'] = otp  # Store the generated OTP in the session for later verification
            # Send the OTP email; if successful, redirect to the OTP verification page
            if send_otp_email(user[1], email, otp):  # Attempt to send the OTP to the user's email address
                return redirect(url_for('verify'))  # If the email is sent successfully, redirect the user to the OTP verification page
        # If credentials are incorrect, redirect back to login with an error message in the query string
        return redirect(url_for('login', error='Incorrect credentials'))  # If authentication fails, redirect back to the login page with an error message
    # For GET requests, render the login page
    return render_template('login.html')  # Render the 'login.html' template for user login

# Route for OTP verification after login
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    # Retrieve an error message from the URL parameters, if any
    error = request.args.get('error')  # Check the query parameters for any error messages to display on the verification page

    if request.method == 'POST':  # Check if the OTP verification form was submitted via POST
        # Get the OTP entered by the user from the form
        entered_otp = request.form.get('otp')  # Retrieve the OTP entered by the user from the submitted form
        # Check if the OTP in session matches the one entered
        if 'otp' in session and session['otp'] == entered_otp:  # Compare the OTP stored in session with the OTP submitted by the user
            # OTP is correct: remove it from the session and redirect to the dashboard
            del session['otp']  # Remove the OTP from the session since it has been successfully verified
            return redirect(url_for('dashboard'))  # Redirect the user to the dashboard (home page) after successful OTP verification
        else:
            # If the OTP is incorrect, redirect back to the verify page with an error message
            return redirect(url_for('verify', error="Invalid OTP, please try again."))  # Redirect back to the OTP verification page with an error message if the OTP does not match
    
    # Render the verify page with any error messages
    return render_template('verify.html', error=error)  # Render the 'verify.html' template, passing any error messages to be displayed

# Route for handling forgotten password requests
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    message = None  # Initialize a variable to hold feedback messages for the user
    message_type = "error"  # Default message type is set to "error" to indicate issues unless overwritten by success

    if request.method == 'POST':  # Check if the forgot password form has been submitted via POST
        # Get the email from the form input
        email = request.form.get('email')  # Retrieve the email address submitted by the user

        # Check if a user with this email exists in the database
        cursor = db.cursor()  # Open a new database cursor for executing queries
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))  # Execute a SELECT query to check if a user exists with the provided email
        user = cursor.fetchone()  # Fetch a single user record from the query result

        if user:
            # Generate a token for password reset and create a reset URL that includes the token
            token = s.dumps(email, salt='password-reset-salt')  # Use the serializer to generate a secure token for the given email with a salt
            reset_url = url_for('resetpassword', token=token, _external=True)  # Build a full URL for the password reset route, embedding the token

            # Prepare an email message with the reset link
            msg = Message('Password Reset Request', recipients=[email])  # Construct an email message with the subject "Password Reset Request" for the user
            msg.body = f'Click the link to reset your password: {reset_url}\n\nThis link will expire in 1 hour.'  # Set the body of the email with the reset URL and expiry notice
            mail.send(msg)  # Send the password reset email using the configured Mail instance

            # Set success message if email was sent
            message = "A password reset link has been sent to your email."  # Inform the user that the reset link has been emailed successfully
            message_type = "success"  # Change the message type to "success" since the operation was successful
        else:
            # Set error message if no user is found with the provided email
            message = "No account found with this email."  # Inform the user that there is no account associated with the provided email

    # Render the forgot password page with the message and its type
    return render_template('forgotpassword.html', message=message, message_type=message_type)  # Render the 'forgotpassword.html' template, passing the message and its type for display

# Route for resetting the password using the token from the reset email
@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def resetpassword(token):
    try:
        # Verify and load the email from the token (token expires in 1 hour)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # Attempt to deserialize the token to retrieve the email, ensuring the token is not older than 1 hour
    except SignatureExpired:
        # If the token has expired, render the reset password page with an error message
        return render_template('resetpassword.html', message="Token expired. Request a new link.", message_type="error")  # Render the reset password page with an error message if the token is expired

    if request.method == 'POST':  # Check if the password reset form has been submitted via POST
        # Get the new password and its confirmation from the form
        password = request.form.get('password')  # Retrieve the new password input from the form
        confirm_password = request.form.get('confirm_password')  # Retrieve the confirmation of the new password from the form

        if password != confirm_password:
            # If passwords do not match, render the page with an error message
            return render_template('resetpassword.html', email=email, message="Passwords do not match!", message_type="error")  # Render the form again with an error if the password and confirmation do not match

        # Hash the new password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())  # Hash the new password securely using bcrypt and a generated salt

        # Update the user's password in the database
        cursor = db.cursor()  # Open a new database cursor
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, email))  # Execute an UPDATE query to change the user's password in the database
        db.commit()  # Commit the transaction to save the updated password

        # Redirect the user to the login page with a success message
        return redirect(url_for('login', message="Password successfully reset. You can now log in.", message_type="success"))  # Redirect to the login page, optionally passing a success message

    # For GET requests, render the reset password form
    return render_template('resetpassword.html', email=email)  # Render the 'resetpassword.html' template and pass the user's email for context

# Route to log out the user by clearing the session
@app.route('/logout')
def logout():
    session.clear()  # Clear all data stored in the session, effectively logging the user out
    return redirect(url_for('login'))  # Redirect the user to the login page after logout

# Route to display product details based on product_id (dynamic route)
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    # Create a cursor that returns dictionary results
    cursor = db.cursor(dictionary=True)  # Open a database cursor that returns rows as dictionaries for easier field access
    # Fetch the product details from the products table by id
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))  # Execute a SELECT query to retrieve product details by its unique ID
    product = cursor.fetchone()  # Fetch the single product record from the query result

    if not product:
        # If no product is found, return a 404 error message
        return "Product not found", 404  # Return a 404 HTTP response with a message if the product ID does not exist in the database

    # Fetch reviews for the product from the reviews table
    cursor.execute("SELECT comment FROM reviews WHERE product_id = %s", (product_id,))  # Execute a query to fetch all review comments for the given product ID
    # Create a list of review comments and assign it to the product dictionary
    product["reviews"] = [row["comment"] for row in cursor.fetchall()]  # Create a list of comments from the fetched review records and add it to the product dictionary under the key "reviews"

    # Render the product detail page with the product data
    return render_template('product_detail.html', product=product)  # Render the 'product_detail.html' template, passing the product data (including reviews) for display

# Route for checkout process of a specific product
@app.route('/checkout/<int:product_id>', methods=['GET', 'POST'])
def checkout(product_id):
    cursor = db.cursor(dictionary=True)  # Open a new database cursor that returns rows as dictionaries
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))  # Execute a query to retrieve the product details by its ID
    product = cursor.fetchone()  # Fetch the product record from the query result
    if not product:
        return "Product not found", 404  # If the product is not found, return a 404 error message

    # Get quantity from query parameters (default is 1)
    quantity = request.args.get('quantity', 1, type=int)  # Retrieve the 'quantity' parameter from the query string, defaulting to 1 if not provided

    if request.method == 'POST':  # Check if the checkout form has been submitted via POST
        address = request.form['address']  # Get the address line from the submitted form data
        city = request.form['city']  # Get the city from the form data
        state = request.form['state']  # Get the state from the form data
        pin = request.form['pin']  # Get the postal pin code from the form data
        full_address = f"{address}, {city}, {state}, {pin}"  # Combine address parts into a full address string
        order_date = datetime.now()  # Capture the current date and time as the order date
        delivery_date = order_date + timedelta(days=5)  # Calculate the delivery date by adding 5 days to the order date
        if 'user_id' not in session:  # Check if the user is logged in by verifying the presence of 'user_id' in the session
            return redirect(url_for('login'))  # If not logged in, redirect the user to the login page
        # Calculate total price based on discounted unit price multiplied by quantity
        discounted_price = product['price'] - (product['price'] * product['discount'] / 100)  # Calculate the discounted price per unit after applying any discount percentage
        total_price = discounted_price * quantity  # Multiply the discounted price by the quantity to get the total order price

        cursor.execute(
            """
            INSERT INTO orders (user_id, product_id, quantity, total_price, address, order_date, delivery_date, status, payment_mode)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, 
            (session['user_id'], product_id, quantity, total_price, full_address, order_date, delivery_date, 'Processing', 'Pending')
        )  # Insert a new order record into the 'orders' table with all relevant details including user_id, product_id, quantity, total_price, shipping address, order and delivery dates, order status, and payment mode
        db.commit()  # Commit the transaction to save the order in the database
        order_id = cursor.lastrowid  # Retrieve the last inserted order's ID from the database
        return redirect(url_for('order_summary', order_id=order_id))  # Redirect the user to the order summary page for the newly created order

    # Pass the quantity to the checkout template so that details are displayed correctly
    return render_template('checkout.html', product=product, quantity=quantity)  # Render the 'checkout.html' template, passing both the product details and the chosen quantity

# Route to display the order summary page for a specific order
@app.route('/order_summary/<int:order_id>')
def order_summary(order_id):
    cursor = db.cursor(dictionary=True)  # Open a new database cursor that returns results as dictionaries
    
    # Fetch order details from the orders table using order_id
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))  # Execute a query to retrieve the order details by order ID
    order = cursor.fetchone()  # Fetch the order record from the query result

    if not order:
        # If the order is not found, flash a message and redirect to home/dashboard
        flash("Order not found!", "danger")  # Use flash to display an error message indicating that the order was not found
        return redirect(url_for('home'))  # Redirect the user to the home/dashboard page
       
    # Fetch product details for the ordered product
    cursor.execute("SELECT * FROM products WHERE id = %s", (order['product_id'],))  # Execute a query to get the product details based on the product_id stored in the order
    product = cursor.fetchone()  # Fetch the product record from the query result

    print("*************", order, product)  # Debugging: print order and product details to the console for debugging purposes

    cursor.close()  # Close the database cursor to free up resources

    # Render the order summary template with order and product details
    return render_template('order_summary.html', order=order, product=product)  # Render the 'order_summary.html' template, passing both the order and associated product details

# Route for processing payments using Razorpay
@app.route('/payment/<int:order_id>')
def payment(order_id):
    # Fetch the order details from the database
    cursor = db.cursor(dictionary=True)  # Open a new database cursor that returns rows as dictionaries
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))  # Execute a query to retrieve the order details for the given order ID
    order = cursor.fetchone()  # Fetch the order record from the query result

    if not order:
        return "Order not found", 404  # If the order is not found, return a 404 error message

    # Fetch product details for the order from the products table
    cursor.execute("SELECT * FROM products WHERE id = %s", (order['product_id'],))  # Execute a query to get the product details for the product associated with the order
    product = cursor.fetchone()  # Fetch the product record from the query result
    
    cursor.close()  # Close the cursor after fetching the required records

    if not product:
        return "Product not found", 404  # If the product is not found, return a 404 error message

    # Calculate the amount in paise for Razorpay (multiply rupees by 100)
    amount = int(product['price']) * 100  # Convert the product price from rupees to paise (as required by Razorpay) by multiplying by 100

    # Create a Razorpay order using the Razorpay client instance
    razorpay_order = razorpay_client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": "1"
    })  # Create a new order with Razorpay by passing the amount, currency (Indian Rupees), and payment_capture flag set to 1 (auto-capture)

    # Store the Razorpay order ID in the order dictionary for further processing
    order['razorpay_order_id'] = razorpay_order['id']  # Add the Razorpay order ID to the order dictionary for tracking and later verification

    # Render the payment page, passing order, product, Razorpay order id, and key to the template
    return render_template('payment.html', order=order, product=product, razorpay_order_id=razorpay_order['id'], razorpay_key=RAZORPAY_KEY_ID)  # Render the 'payment.html' template with all necessary details for completing the payment

# Route to handle payment success after processing the payment
@app.route('/payment_success/<int:order_id>', methods=['POST'])
def payment_success(order_id):
    cursor = db.cursor(dictionary=True)  # Open a new database cursor that returns rows as dictionaries
    # Fetch the order details
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))  # Execute a query to get the details of the order by its ID
    order = cursor.fetchone()  # Fetch the order record from the query result
    if not order:
        return "Order not found", 404  # Return a 404 error message if the order does not exist

    # Fetch the product details
    cursor.execute("SELECT * FROM products WHERE id = %s", (order['product_id'],))  # Execute a query to fetch the product details for the product in the order
    product = cursor.fetchone()  # Fetch the product record from the query result
    if not product:
        return "Product not found", 404  # Return a 404 error message if the product does not exist

    # Retrieve payment details from the form
    payment_id = request.form.get("razorpay_payment_id")  # Get the payment ID from the submitted form data (sent by Razorpay)
    razorpay_order_id = request.form.get("razorpay_order_id")  # Get the Razorpay order ID from the form data
    signature = request.form.get("razorpay_signature")  # Get the payment signature from the form data for verification
    if not payment_id or not razorpay_order_id or not signature:
        return "Missing payment details", 400  # If any required payment detail is missing, return a 400 Bad Request error

    # Prepare the parameters for signature verification
    params_dict = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }  # Create a dictionary containing all payment details required to verify the payment signature with Razorpay

    try:
        # Verify the payment signature
        razorpay_client.utility.verify_payment_signature(params_dict)  # Call the Razorpay utility function to verify the authenticity of the payment details using the provided signature
        # Update the order status to "Order Placed" after successful payment
        cursor.execute(
            """
            UPDATE orders 
            SET status = %s, payment_status = %s, payment_mode = %s
            WHERE id = %s
            """, 
            ("Shipped", "Completed", "Razorpay", order_id)
        )  # Update the order record in the database to reflect that payment has been completed and the order is now shipped, along with the payment mode used
        db.commit()  # Commit the transaction to save the updated order status
        cursor.close()  # Close the database cursor
        # Render payment_success.html (make sure this template shows the updated status)
        return render_template('payment_success.html', order=order, product=product)  # Render the 'payment_success.html' template to inform the user that the payment was successful, along with order and product details
    except razorpay.errors.SignatureVerificationError:
        return "Payment verification failed", 400  # If signature verification fails, return a 400 Bad Request error indicating that the payment could not be verified

# Route to add a product order (currently a placeholder)
@app.route('/add_order')
def add_order():
    # Redirect to dashboard after adding an order (functionality to be implemented)
    return redirect(url_for('dashboard'))  # Currently, simply redirect to the dashboard; this route may be expanded later to add order functionality

# Route to add a product to cart
@app.route('/add_cart/<int:product_id>')
def add_cart(product_id):
    # Ensure user is logged in
    if 'user_id' not in session:  # Check if the user is authenticated by verifying the session for 'user_id'
        return redirect(url_for('login'))  # If not logged in, redirect to the login page
    
    cursor = db.cursor()  # Open a new database cursor
    # Check if the product already exists in the user's cart
    cursor.execute("SELECT id, quantity FROM cart WHERE user_id = %s AND product_id = %s", (session['user_id'], product_id))  # Execute a SELECT query to determine if the product is already in the user's cart
    existing = cursor.fetchone()  # Fetch any existing cart entry for the product
    if existing:
        # Increase quantity by 1 (and the effective price doubles accordingly)
        new_qty = existing[1] + 1  # Increment the existing quantity by 1
        cursor.execute("UPDATE cart SET quantity = %s WHERE id = %s", (new_qty, existing[0]))  # Update the cart record with the new quantity
    else:
        # Insert new cart entry with quantity 1
        cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)", (session['user_id'], product_id, 1))  # Insert a new record into the cart with quantity set to 1 if the product is not already present
    db.commit()  # Commit the transaction to save changes in the cart
    return redirect(url_for('cart'))  # Redirect the user to the cart page to review the updated cart

# Route to display the cart page with all added items
@app.route('/cart')
def cart():
    if 'user_id' not in session:  # Ensure the user is logged in by checking for 'user_id' in session
        return redirect(url_for('login'))  # If not authenticated, redirect to the login page
    
    cursor = db.cursor(dictionary=True)  # Open a new database cursor that returns rows as dictionaries
    # Join cart with products table to get product details
    query = """
        SELECT c.id AS cart_id, c.product_id, c.quantity, p.name, p.price, p.discount, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s
    """  # Define a SQL query that joins the 'cart' and 'products' tables to fetch complete details for items in the user's cart
    cursor.execute(query, (session['user_id'],))  # Execute the query with the current user's ID as parameter
    items = cursor.fetchall()  # Fetch all resulting cart items with product details into a list
    
    grand_total = 0  # Initialize a variable to accumulate the grand total price for the cart
    for item in items:  # Iterate over each cart item
        # Calculate discounted price for one unit
        discounted_price = item['price'] - (item['price'] * item['discount'] / 100)  # Calculate the effective price after applying the discount on the product price
        item['discounted_price'] = discounted_price  # Add the calculated discounted price to the item's dictionary for later use
        # Total price = discounted price * quantity
        item['total_price'] = discounted_price * item['quantity']  # Calculate the total price for this cart item based on its quantity and discounted price
        grand_total += item['total_price']  # Accumulate the total price into the grand total for the entire cart
    
    cursor.close()  # Close the database cursor after fetching and processing all cart items
    return render_template('cart.html', items=items, grand_total=grand_total)  # Render the 'cart.html' template with the list of cart items and the grand total price

# Route to delete a cart item
@app.route('/delete_cart/<int:cart_id>')
def delete_cart(cart_id):
    if 'user_id' not in session:  # Verify that the user is logged in by checking for 'user_id' in session
        return redirect(url_for('login'))  # If the user is not authenticated, redirect them to the login page
    
    cursor = db.cursor()  # Open a new database cursor
    cursor.execute("DELETE FROM cart WHERE id = %s AND user_id = %s", (cart_id, session['user_id']))  # Execute a DELETE query to remove the cart item identified by cart_id for the logged-in user only
    db.commit()  # Commit the deletion to the database
    return redirect(url_for('cart'))  # Redirect the user back to the cart page to view the updated cart




# -----------------------
# FAVORITES FUNCTIONALITY
# -----------------------

# Define a route to add a product to the user's favorites (wishlist)
@app.route('/add_favorite/<int:product_id>')
def add_favorite(product_id):
    """
    Adds a product to the user's favorites (wishlist).
    If the user is not logged in, redirects to login.
    """
    # Check if the user is logged in by verifying the existence of 'user_id' in session
    if 'user_id' not in session:
        # If not logged in, redirect the user to the login page
        return redirect(url_for('login'))

    # Create a new database cursor to execute SQL queries
    cursor = db.cursor()
    # Check if the product is already present in the wishlist for the current user
    cursor.execute("""
        SELECT id 
        FROM wishlist 
        WHERE user_id = %s AND product_id = %s
    """, (session['user_id'], product_id))  # Pass current user id and product id as parameters
    existing = cursor.fetchone()  # Fetch one record from the query result

    # If the product is not already in the wishlist, add it
    if not existing:
        # Insert a new record into the wishlist table with the current user's id and the product id
        cursor.execute("""
            INSERT INTO wishlist (user_id, product_id) 
            VALUES (%s, %s)
        """, (session['user_id'], product_id))
        db.commit()  # Commit the transaction to save changes to the database

    # Close the database cursor to free up resources
    cursor.close()
    # Redirect the user to the favorites page (or alternatively to 'dashboard' if preferred)
    return redirect(url_for('favorites'))

# Define a route to display all favorite products for the logged-in user
@app.route('/favorites')
def favorites():
    """
    Displays all favorite products for the logged-in user.
    If user not logged in, redirects to login.
    """
    # Check if the user is logged in by checking for 'user_id' in session
    if 'user_id' not in session:
        # If not logged in, redirect to the login page
        return redirect(url_for('login'))

    # Create a new database cursor that returns results as dictionaries
    cursor = db.cursor(dictionary=True)
    # Join the wishlist and products tables to fetch product details for each favorite item
    cursor.execute("""
        SELECT 
            w.id AS wishlist_id,
            p.id AS product_id,
            p.name,
            p.price,
            p.discount,
            p.quantity AS stock,
            p.image
        FROM wishlist w
        JOIN products p ON w.product_id = p.id
        WHERE w.user_id = %s
    """, (session['user_id'],))  # Pass the current user id to filter favorites
    favorite_items = cursor.fetchall()  # Fetch all favorite items from the query result
    cursor.close()  # Close the cursor after retrieving data

    # Render the 'favorites.html' template and pass the list of favorite items
    return render_template('favorites.html', items=favorite_items)

# Define a route to remove a product from the user's favorites (wishlist)
@app.route('/remove_favorite/<int:wishlist_id>')
def remove_favorite(wishlist_id):
    """
    Removes a favorite item from the wishlist by wishlist ID.
    Only if the user is logged in and owns the wishlist entry.
    """
    # Check if the user is logged in by verifying the 'user_id' in session
    if 'user_id' not in session:
        # Redirect to login if the user is not authenticated
        return redirect(url_for('login'))

    # Create a new database cursor
    cursor = db.cursor()
    # Execute a DELETE query to remove the wishlist item, ensuring it belongs to the logged-in user
    cursor.execute("""
        DELETE FROM wishlist 
        WHERE id = %s AND user_id = %s
    """, (wishlist_id, session['user_id']))
    db.commit()  # Commit the transaction to remove the item from the database
    cursor.close()  # Close the cursor

    # Redirect the user back to the favorites page after removal
    return redirect(url_for('favorites'))


# -------------------
# MY ORDERS FUNCTIONALITY
# -------------------

# Define a route to display all orders for the logged-in user in a table/grid format
@app.route('/my_orders')
def my_orders():
    """
    Displays all orders for the logged-in user in a table/grid.
    Each order shows product details, status, date, etc.
    """
    # Verify that the user is logged in by checking for 'user_id' in session
    if 'user_id' not in session:
        # Redirect the user to the login page if not authenticated
        return redirect(url_for('login'))

    # Create a new database cursor that returns rows as dictionaries
    cursor = db.cursor(dictionary=True)
    # SQL query to join orders with products table to display product details along with the order information
    query = """
        SELECT 
            o.id AS order_id,
            o.product_id,
            o.quantity,
            o.total_price,
            o.address,
            o.order_date,
            o.delivery_date,
            o.status,
            p.name AS product_name,
            p.image AS product_image
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = %s
        ORDER BY o.order_date DESC
    """
    # Execute the query, passing the current user's id to retrieve only their orders
    cursor.execute(query, (session['user_id'],))
    orders = cursor.fetchall()  # Fetch all the orders from the query result
    cursor.close()  # Close the cursor after retrieving the data

    # Render the 'my_orders.html' template and pass the orders data for display
    return render_template('my_orders.html', orders=orders)

# Define a route to cancel an order for the logged-in user
@app.route('/cancel_order/<int:order_id>')
def cancel_order(order_id):
    # Check if the user is logged in by verifying 'user_id' in session
    if 'user_id' not in session:
        # If not logged in, redirect to the login page
        return redirect(url_for('login'))

    # Create a new database cursor that returns rows as dictionaries
    cursor = db.cursor(dictionary=True)
    # Fetch the current status of the order to verify if cancellation is allowed
    cursor.execute("SELECT status FROM orders WHERE id=%s AND user_id=%s", (order_id, session['user_id']))
    order = cursor.fetchone()  # Retrieve the order record from the query result

    # If no order is found or the order doesn't belong to the user, close the cursor and redirect
    if not order:
        cursor.close()
        return redirect(url_for('my_orders'))
    
    # Allow cancellation only if the order's current status is "Processing"
    if order['status'] == 'Processing':
        # Update the order's status to 'Cancelled' in the database
        cursor.execute("UPDATE orders SET status='Cancelled' WHERE id=%s", (order_id,))
        db.commit()  # Commit the transaction to save the change

    cursor.close()  # Close the cursor
    # Redirect the user back to the orders page
    return redirect(url_for('my_orders'))

# Define a route to allow a user to request a return for a delivered order
@app.route('/return_order/<int:order_id>')
def return_order(order_id):
    """
    Allows a user to request a return if the order is 'Delivered'.
    This is just an example; you can adapt the logic as you like.
    """
    # Verify the user is logged in by checking for 'user_id' in session
    if 'user_id' not in session:
        # Redirect to login if the user is not authenticated
        return redirect(url_for('login'))

    # Create a new database cursor that returns rows as dictionaries
    cursor = db.cursor(dictionary=True)
    # Fetch the order's status to determine if a return is eligible
    cursor.execute("SELECT status FROM orders WHERE id=%s AND user_id=%s", (order_id, session['user_id']))
    order = cursor.fetchone()  # Retrieve the order record

    # If no order is found or it doesn't belong to the user, close the cursor and redirect to orders page
    if not order:
        cursor.close()
        return redirect(url_for('my_orders'))

    # Allow a return request only if the order status is 'Delivered'
    if order['status'] == 'Delivered':
        # Update the order's status to 'Returned' in the database
        cursor.execute("UPDATE orders SET status='Returned' WHERE id=%s", (order_id,))
        db.commit()  # Commit the transaction to update the status

    cursor.close()  # Close the database cursor
    # Redirect the user back to the orders page
    return redirect(url_for('my_orders'))

# Define a route to permanently delete an order from the database (only for the logged-in user)
@app.route('/delete_order/<int:order_id>')
def delete_order(order_id):
    """
    Permanently removes an order from the database 
    (for the logged-in user only).
    """
    # Verify that the user is logged in by checking for 'user_id' in session
    if 'user_id' not in session:
        # Redirect to login page if not logged in
        return redirect(url_for('login'))

    # Create a new database cursor that returns rows as dictionaries
    cursor = db.cursor(dictionary=True)
    # Verify that the order exists and belongs to the logged-in user by checking the order id and user id
    cursor.execute("SELECT id FROM orders WHERE id=%s AND user_id=%s", (order_id, session['user_id']))
    order = cursor.fetchone()  # Retrieve the order record

    # If the order does not exist or does not belong to the user, close the cursor and redirect to orders page
    if not order:
        cursor.close()
        return redirect(url_for('my_orders'))

    # Delete the order from the orders table
    cursor.execute("DELETE FROM orders WHERE id=%s", (order_id,))
    db.commit()  # Commit the deletion to permanently remove the order
    cursor.close()  # Close the cursor

    # Redirect the user back to the orders page after deletion
    return redirect(url_for('my_orders'))

# Define a route to render the About page
@app.route('/about')
def about():
    """
    Renders the About page.
    """
    # Render the 'about.html' template for displaying the About page information
    return render_template('about.html')

# Define a route for contact that redirects to the dashboard (could be adapted to a separate contact page)
@app.route('/contact')
def contact():
    # Redirect the user to the dashboard page when accessing the contact route
    return redirect(url_for('dashboard'))

# Run the Flask application on port 6002 in debug mode if this script is executed directly
if __name__ == "__main__":
    # Start the Flask development server on port 6002 with debug mode enabled for development purposes
    app.run(port=6002, debug=True)
    # The following lines are commented out alternatives for deployment configuration:
    # import os
    # port = int(os.environ.get("PORT", 6002))
    # app.run(host="0.0.0.0", port=port, debug=True)


# Import necessary functions and classes from Flask and other libraries
from flask import Flask, render_template, redirect, url_for, request, session, flash
# Flask-Mail is used for sending emails from our Flask app
from flask_mail import Mail, Message
# itsdangerous is used to generate secure tokens for actions like password reset
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
# random module to generate random numbers (used for OTP generation)
import random
# Import the database connection (assumed to be set up in a separate module 'database')
from database import db
# datetime and timedelta are used for time-related operations (e.g., calculating delivery dates)
from datetime import datetime, timedelta
# Razorpay is used for payment processing
import razorpay
# bcrypt is used for hashing passwords securely
import bcrypt

import os
from decimal import Decimal

# (Optional) MySQL connector is commented out because we are using our own database module
# import mysql.connector

# Initialize the Flask application
app = Flask(__name__)
# Set the secret key for session management and security (used for signing cookies and tokens)
app.secret_key = os.environ.get("SECRET_KEY", "simplelogin")

# Razorpay configuration: API key and secret for integrating Razorpay payment gateway
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID","rzp_test_xxfkdUYWCKHS4E" )      # Replace with your actual Razorpay key ID in production
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET","DDFK36eIKqNL514rmiJ4vahF")   # Replace with your actual Razorpay key secret

# Create a Razorpay client instance using the provided API credentials
razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# Configure Flask-Mail settings for sending emails
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME", "thadkapallysaikiran2001@gmail.com")  # Sender email address
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD", "ktvq inal srse itjg")                 # Sender email password
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER", "thadkapallysaikiran2001@gmail.com")

# Initialize Flask-Mail with the app configuration
mail = Mail(app)
# Initialize a URLSafeTimedSerializer with the app's secret key for token generation (e.g., password reset)
s = URLSafeTimedSerializer(app.secret_key)

# Function to generate a 6-digit OTP as a string
def generate_otp():
    return str(random.randint(100000, 999999))

# Function to send an OTP email using Flask-Mail
def send_otp_email(name, email, otp):
    try:
        # Create an email message with subject and recipient
        msg = Message('OTP for Verification', recipients=[email])
        # Set the body of the email with a personalized message including the OTP
        msg.body = f"Hello {name}!\nYour OTP is: {otp}"
        # Send the email
        mail.send(msg)
        return True
    except Exception as e:
        # Print any error that occurs during email sending and return False
        print("Error sending email:", e)
        return False

# Route for the dashboard (home page of the store)
@app.route('/')
def dashboard():
    # Create a cursor that returns results as dictionaries
    cursor = db.cursor(dictionary=True)
    # Execute SQL query to fetch all products from the products table
    cursor.execute("SELECT * FROM products")
    # Fetch all rows from the query result
    products = cursor.fetchall()
    # Render the dashboard template with the fetched products
    return render_template('dashboard.html', products=products)

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve user input from the form fields
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        # Hash the password using bcrypt for secure storage
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Insert new user into the users table
        cursor = db.cursor()
        cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
        db.commit()
        
        # After successful registration, redirect to the login page
        return redirect(url_for('login'))
    # For GET requests, simply render the registration page
    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Retrieve email and password from the login form
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Query the users table to fetch user details for the given email
        cursor = db.cursor()
        cursor.execute("SELECT id, username, password FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        
        # Check if user exists and the password matches (using bcrypt for comparison)
        if user and bcrypt.checkpw(password.encode('utf-8'), user[2].encode('utf-8')):
            # Set session variables for the logged-in user
            session['user_id'] = user[0]
            session['username'] = user[1]
            # Generate an OTP and store it in the session for verification
            otp = generate_otp()
            session['otp'] = otp
            # Send the OTP email; if successful, redirect to the OTP verification page
            if send_otp_email(user[1], email, otp):
                return redirect(url_for('verify'))
        # If credentials are incorrect, redirect back to login with an error message in the query string
        return redirect(url_for('login', error='Incorrect credentials'))
    # For GET requests, render the login page
    return render_template('login.html')

# Route for OTP verification after login
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    # Retrieve an error message from the URL parameters, if any
    error = request.args.get('error')

    if request.method == 'POST':
        # Get the OTP entered by the user from the form
        entered_otp = request.form.get('otp')
        # Check if the OTP in session matches the one entered
        if 'otp' in session and session['otp'] == entered_otp:
            # OTP is correct: remove it from the session and redirect to the dashboard
            del session['otp']
            return redirect(url_for('dashboard'))
        else:
            # If the OTP is incorrect, redirect back to the verify page with an error message
            return redirect(url_for('verify', error="Invalid OTP, please try again."))
    
    # Render the verify page with any error messages
    return render_template('verify.html', error=error)

# Route for handling forgotten password requests
@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    message = None
    message_type = "error"  # Default message type is error

    if request.method == 'POST':
        # Get the email from the form input
        email = request.form.get('email')

        # Check if a user with this email exists in the database
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            # Generate a token for password reset and create a reset URL that includes the token
            token = s.dumps(email, salt='password-reset-salt')
            reset_url = url_for('resetpassword', token=token, _external=True)

            # Prepare an email message with the reset link
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_url}\n\nThis link will expire in 1 hour.'
            mail.send(msg)

            # Set success message if email was sent
            message = "A password reset link has been sent to your email."
            message_type = "success"
        else:
            # Set error message if no user is found with the provided email
            message = "No account found with this email."

    # Render the forgot password page with the message and its type
    return render_template('forgotpassword.html', message=message, message_type=message_type)

# Route for resetting the password using the token from the reset email
@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def resetpassword(token):
    try:
        # Verify and load the email from the token (token expires in 1 hour)
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        # If the token has expired, render the reset password page with an error message
        return render_template('resetpassword.html', message="Token expired. Request a new link.", message_type="error")

    if request.method == 'POST':
        # Get the new password and its confirmation from the form
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            # If passwords do not match, render the page with an error message
            return render_template('resetpassword.html', email=email, message="Passwords do not match!", message_type="error")

        # Hash the new password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Update the user's password in the database
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed_password, email))
        db.commit()

        # Redirect the user to the login page with a success message
        return redirect(url_for('login', message="Password successfully reset. You can now log in.", message_type="success"))

    # For GET requests, render the reset password form
    return render_template('resetpassword.html', email=email)

# Route to log out the user by clearing the session
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Route to display product details based on product_id (dynamic route)
@app.route('/product/<int:product_id>')
def product_detail(product_id):
    # Create a cursor that returns dictionary results
    cursor = db.cursor(dictionary=True)
    # Fetch the product details from the products table by id
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if not product:
        # If no product is found, return a 404 error message
        return "Product not found", 404

    # Fetch reviews for the product from the reviews table
    cursor.execute("SELECT comment FROM reviews WHERE product_id = %s", (product_id,))
    # Create a list of review comments and assign it to the product dictionary
    product["reviews"] = [row["comment"] for row in cursor.fetchall()]

    # Render the product detail page with the product data
    return render_template('product_detail.html', product=product)

@app.route('/checkout/<int:product_id>', methods=['GET', 'POST'])
def checkout(product_id):
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    if not product:
        return "Product not found", 404

    # Get quantity from query parameters (default is 1)
    quantity = request.args.get('quantity', 1, type=int)

    if request.method == 'POST':
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        pin = request.form['pin']
        full_address = f"{address}, {city}, {state}, {pin}"
        order_date = datetime.now()
        delivery_date = order_date + timedelta(days=5)
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # Calculate total price based on discounted unit price multiplied by quantity
        discounted_price = product['price'] - (product['price'] * product['discount'] / 100)
        total_price = discounted_price * quantity

        cursor.execute(
            """
            INSERT INTO orders (user_id, product_id, quantity, total_price, address, order_date, delivery_date, status, payment_mode)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, 
            (session['user_id'], product_id, quantity, total_price, full_address, order_date, delivery_date, 'Processing', 'Pending')
        )
        db.commit()
        order_id = cursor.lastrowid
        return redirect(url_for('order_summary', order_id=order_id))

    # Pass the quantity to the checkout template so that details are displayed correctly
    return render_template('checkout.html', product=product, quantity=quantity)


# Route to display the order summary page for a specific order
@app.route('/order_summary/<int:order_id>')
def order_summary(order_id):
    cursor = db.cursor(dictionary=True)
    
    # Fetch order details from the orders table using order_id
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
    order = cursor.fetchone()

    if not order:
        # If the order is not found, flash a message and redirect to home/dashboard
        flash("Order not found!", "danger")
        return redirect(url_for('home'))
    
    # Fetch product details for the ordered product
    cursor.execute("SELECT * FROM products WHERE id = %s", (order['product_id'],))
    product = cursor.fetchone()

    print("*************", order, product)  # Debugging: print order and product details

    cursor.close()

    # Render the order summary template with order and product details
    return render_template('order_summary.html', order=order, product=product)

# Route for processing payments using Razorpay
@app.route('/payment/<int:order_id>')
def payment(order_id):
    # Fetch the order details from the database
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
    order = cursor.fetchone()

    if not order:
        return "Order not found", 404

    # Fetch product details for the order from the products table
    cursor.execute("SELECT * FROM products WHERE id = %s", (order['product_id'],))
    product = cursor.fetchone()
    
    cursor.close()

    if not product:
        return "Product not found", 404

    # Calculate the amount in paise for Razorpay (multiply rupees by 100)
    amount = int(product['price']) * 100

    # Create a Razorpay order using the Razorpay client instance
    razorpay_order = razorpay_client.order.create({
        "amount": amount,
        "currency": "INR",
        "payment_capture": "1"
    })

    # Store the Razorpay order ID in the order dictionary for further processing
    order['razorpay_order_id'] = razorpay_order['id']

    # Render the payment page, passing order, product, Razorpay order id, and key to the template
    return render_template('payment.html', order=order, product=product, razorpay_order_id=razorpay_order['id'], razorpay_key=RAZORPAY_KEY_ID)

# Route to handle payment success after processing the payment
@app.route('/payment_success/<int:order_id>', methods=['POST'])
def payment_success(order_id):
    cursor = db.cursor(dictionary=True)

    # Fetch the order details from the orders table
    cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))
    order = cursor.fetchone()

    if not order:
        return "Order not found", 404

    # Fetch product details related to the order from the products table
    cursor.execute("SELECT * FROM products WHERE id = %s", (order['product_id'],))
    product = cursor.fetchone()

    if not product:
        return "Product not found", 404

    # Retrieve payment details from the form submitted by Razorpay
    payment_id = request.form.get("razorpay_payment_id")
    razorpay_order_id = request.form.get("razorpay_order_id")
    signature = request.form.get("razorpay_signature")

    print("Received Payment ID:", payment_id)
    print("Received Order ID:", razorpay_order_id)
    print("Received Signature:", signature)

    # Ensure all payment details are present
    if not payment_id or not razorpay_order_id or not signature:
        return "Missing payment details", 400

    # Prepare a dictionary of payment details for signature verification
    params_dict = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }

    try:
        # Verify the payment signature to ensure the payment is secure
        razorpay_client.utility.verify_payment_signature(params_dict)
        # If verification is successful, update the order status and payment details in the database
        cursor.execute(
            """
            UPDATE orders 
            SET status = %s, payment_status = %s, payment_mode = %s
            WHERE id = %s
            """, 
            ("Processing", "Completed", "Razorpay", order_id)
        )

        cursor.close()

        # Render the payment success page with order and product details
        return render_template('payment_success.html', order=order, product=product)
    
    except razorpay.errors.SignatureVerificationError:
        # If signature verification fails, return an error response
        return "Payment verification failed", 400

# Dummy routes for favorite, order, and cart functionalities
@app.route('/add_favorite')
def add_favorite():
    # Redirect to dashboard after adding a favorite (functionality to be implemented)
    return redirect(url_for('dashboard'))

@app.route('/add_order')
def add_order():
    # Redirect to dashboard after adding an order (functionality to be implemented)
    return redirect(url_for('dashboard'))


# Route to add a product to cart
@app.route('/add_cart/<int:product_id>')
def add_cart(product_id):
    # Ensure user is logged in
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = db.cursor()
    # Check if the product already exists in the user's cart
    cursor.execute("SELECT id, quantity FROM cart WHERE user_id = %s AND product_id = %s", (session['user_id'], product_id))
    existing = cursor.fetchone()
    if existing:
        # Increase quantity by 1 (and the effective price doubles accordingly)
        new_qty = existing[1] + 1
        cursor.execute("UPDATE cart SET quantity = %s WHERE id = %s", (new_qty, existing[0]))
    else:
        # Insert new cart entry with quantity 1
        cursor.execute("INSERT INTO cart (user_id, product_id, quantity) VALUES (%s, %s, %s)", (session['user_id'], product_id, 1))
    db.commit()
    return redirect(url_for('cart'))


# Route to display the cart page with all added items
@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = db.cursor(dictionary=True)
    # Join cart with products table to get product details
    query = """
        SELECT c.id AS cart_id, c.product_id, c.quantity, p.name, p.price, p.discount, p.image
        FROM cart c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = %s
    """
    cursor.execute(query, (session['user_id'],))
    items = cursor.fetchall()
    
    grand_total = 0
    for item in items:
        # Calculate discounted price for one unit
        discounted_price = item['price'] - (item['price'] * item['discount'] / 100)
        item['discounted_price'] = discounted_price
        # Total price = discounted price * quantity
        item['total_price'] = discounted_price * item['quantity']
        grand_total += item['total_price']
    
    cursor.close()
    return render_template('cart.html', items=items, grand_total=grand_total)


# Route to delete a cart item
@app.route('/delete_cart/<int:cart_id>')
def delete_cart(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cursor = db.cursor()
    cursor.execute("DELETE FROM cart WHERE id = %s AND user_id = %s", (cart_id, session['user_id']))
    db.commit()
    return redirect(url_for('cart'))


# Dummy routes for about and contact pages that redirect to dashboard (placeholders)
@app.route('/about')
def about():
    return redirect(url_for('dashboard'))

@app.route('/contact')
def contact():
    return redirect(url_for('dashboard'))

# Run the Flask application on port 6002 in debug mode
if __name__ == "__main__":
    app.run(port=6002, debug=True)
    # import os
    # port = int(os.environ.get("PORT", 6002))
    # app.run(host="0.0.0.0", port=port, debug=True)


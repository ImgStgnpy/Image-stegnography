from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads/'

# Function to generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    image_file = request.files['image']
    pdf_file = request.files['pdf']
    password = request.form['password']
    
    if not image_file or not pdf_file or not password:
        flash('All fields are required!')
        return redirect(url_for('index'))

    image_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(image_file.filename))
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(pdf_file.filename))
    
    image_file.save(image_path)
    pdf_file.save(pdf_path)
    
    # Add your encoding logic here
    # Use the generate_key function with the password
    
    return "PDF Encoded Successfully"

@app.route('/decode', methods=['POST'])
def decode():
    image_file = request.files['image']
    password = request.form['password']

    if not image_file or not password:
        flash('All fields are required!')
        return redirect(url_for('index'))

    image_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(image_file.filename))
    
    # Add your decoding logic here
    # Use the generate_key function with the password

    return "PDF Decoded Successfully"

if __name__ == '__main__':
    app.run(debug=True)

from flask import Flask, request, session
from flask_cors import CORS
import pymongo
import bcrypt
import requests
import re

app = Flask(__name__)
app.secret_key = "super secret key"

# try to connect to the database
try:
    client = pymongo.MongoClient(
        "mongodb+srv://YingzhouJiang:Jyz1996!@cluster0.zkmuv24.mongodb.net/?retryWrites=true&w=majority", serverSelectionTimeoutMS=5000)
    print("Connected database successfully!")
except:
    print("Unable to connect to the server.")

db = client['ufit_test']
users = db['accounts']

# create a new authentication user
@app.route('/register', methods=['POST'])
def register():
    # get the data from the request
    data = request.get_json()
    name = data['name']
    email = data['email']
    password = data['password']
    password2 = data['password2']
    
    if not name or not email or not password or not password2:
        return "Please fill out all the fields", 400
    
    # check if the email is valid
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email address", 400
    
    # check if the password is valid
    if len(password) < 8:
        return "Password must be at least 8 characters", 400
    
    # check if the password matches
    if password != password2:
        return "Passwords must match", 400
    
    # check if the email already exists
    existing_user = users.find_one({"email": email})
    if existing_user is not None:
        return "Email already exists", 400
    
    # hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # insert the new user into the database
    users.insert_one({"name": name, "email": email, "password": hashed})
    
    return "Success", 200


# login authentication
@app.route('/login', methods=['POST'])
def login():
    # get the data from the request
    data = request.get_json()
    email = data['email']
    password = data['password']
    
    if not email or not password:
        return "Please fill out all the fields", 400
    
    # check if the email is valid
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email address", 400
    
    # check if the password is valid
    if len(password) < 8:
        return "Password must be at least 8 characters", 400
    
    # check if the email not exists
    existing_user = users.find_one({"email": email})
    if existing_user is None:
        return "Email not exists", 400
    
    # check if the password matches
    if bcrypt.checkpw(password.encode('utf-8'), existing_user['password']):
        session['email'] = email
        return "Success", 200
    else:
        return "Incorrect password", 400
    
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return "Success", 200


# reset password
@app.route('/reset', methods=['POST'])
def reset():
    # get the data from the request
    data = request.get_json()
    email = data['email']
    password = data['password']
    password2 = data['password2']
    
    if not email or not password or not password2:
        return "Please fill out all the fields", 400
    
    # check if the email is valid
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return "Invalid email address", 400
    
    # check if the password is valid
    if len(password) < 8:
        return "Password must be at least 8 characters", 400
    
    # check if the password matches
    if password != password2:
        return "Passwords must match", 400
    
    # check if the email not exists
    existing_user = users.find_one({"email": email})
    if existing_user is None:
        return "Email not exists", 400
    
    # hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # update the password
    users.update_one({"email": email}, {"$set": {"password": hashed}})
    
    return "Success", 200


# delete account
@app.route('/delete', methods=['POST'])
def delete():
    data = request.get_json()
    email = data['email']
    password = data['password']

    # check email is exist
    existing_user = users.find_one({"email": email})
    if existing_user is None:
        return "Email not exists", 400

    # check password is correct
    if bcrypt.checkpw(password.encode('utf-8'), existing_user['password']):
        users.delete_one({"email": email})
        return "Success", 200
    else:
        return "Incorrect password", 400


# end of code to run it
if __name__ == "__main__":
    app.run(debug=True)

'''
@author Sashi Vardhan Reddy Chandra

@date: 25/11/2021
'''

from flask import Flask, render_template, request, url_for, redirect, session

# imported libraries from external dependencies
import pymongo
import bcrypt

app = Flask(__name__)
app.secret_key = "testing"

# connection of mongodb through the pymongo library Using MongoClient
client = pymongo.MongoClient(
    "mongodb+srv://schandra:Sashi@cluster0.levop.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")

    # Creating a Cluster as 'flask_users_database'
db = client.get_database('flask_users_database')

    # Creating a collection as 'users_registers
records = db.users_registers


'''
@ description: Used to stored the users data in the MONGO database(creating the users account) and authentication of user

@params : fullname, email, password, confirmpassword
@return if logged_in else sign up

'''
@app.route("/", methods=['post', 'get'])
def index():
    message = ''

        # if user login through the email, session is started and running upto the user logout
    if "email" in session:
        return redirect(url_for("logged_in"))

      # send the data through the http POST method to the database through the server  
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")

        password1 = request.form.get("password")
        password2 = request.form.get("confirmpassword")

        # checking the user details in the database if match shows the appropriate message to user
        user_found = records.find_one({"fullname": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('signup.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('signup.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('signup.html', message=message)
            # encrypt the user password
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'fullname': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)

            user_data = records.find_one({"email": email})
            new_email = user_data['email']

            return render_template('logged_in.html', email=new_email)
    return render_template('signup.html')


#end of code to run it
if __name__ == "__main__":
  app.run(debug=True)



'''
@ description: Used to show the user email in the logged_in component like session started

@params : email
@return if logged_in else login components

'''
@app.route('/logged_in')
def logged_in():
    if "email" in session:
        email = session["email"]
        return render_template('logged_in.html', email=email)
    else:
        return redirect(url_for("login"))



'''
@ description: Used to login the user account

@params : email and password
@return if logged_in else login components

'''

@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("logged_in"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('logged_in'))
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)




'''

@ description: Used to logout the user account, session is terminated

@params : email and password
@return if logged_in else login components

'''

@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return render_template("logout.html")
    else:
        return render_template('signin.html')

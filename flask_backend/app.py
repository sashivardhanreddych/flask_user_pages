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



@app.route("/", methods=['post', 'get'])
def index():
    message = ''
    if "email" in session:
        return redirect(url_for("logged_in"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")

        password1 = request.form.get("password")
        password2 = request.form.get("confirmpassword")

        user_found = records.find_one({"name": user})
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
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)

            user_data = records.find_one({"email": email})
            new_email = user_data['email']

            return render_template('logged_in.html', email=new_email)
    return render_template('signup.html')


#end of code to run it
if __name__ == "__main__":
  app.run(debug=True)

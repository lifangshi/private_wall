from flask import Flask, render_template, request, redirect, session, flash
import re
import mysqlconnection
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key="keep it secret, keep it safe"
bcrypt = Bcrypt(app)


def selection_sort(L):
    for i in range(len(L)): 
        # Find the minimum element in remaining  
        # unsorted array 
        min_idx = i 
        for j in range(i+1, len(L)): 
            if L[min_idx]['first_name'] > L[j]['first_name']: 
                min_idx = j 
        # Swap the found minimum element with  
        # the first element         
        L[i], L[min_idx] = L[min_idx], L[i] 


def pretty_date(time=False):
    """
    Get a datetime object or a int() Epoch timestamp and return a
    pretty string like 'an hour ago', 'Yesterday', '3 months ago',
    'just now', etc
    """
    from datetime import datetime
    now = datetime.now()
    if type(time) is int:
        diff = now - datetime.fromtimestamp(time)
    elif isinstance(time,datetime):
        diff = now - time
    elif not time:
        diff = now - now
    second_diff = diff.seconds
    day_diff = diff.days

    if day_diff < 0:
        return ''

    if day_diff == 0:
        if second_diff < 10:
            return "just now"
        if second_diff < 60:
            return str(second_diff) + " seconds ago"
        if second_diff < 120:
            return "a minute ago"
        if second_diff < 3600:
            return str(int(round(second_diff / 60,0)))+ " minutes ago"
        if second_diff < 7200:
            return "an hour ago"
        if second_diff < 86400:
            return str(int(round(second_diff / 3600,0))) + " hours ago"
    if day_diff == 1:
        return "Yesterday"
    if day_diff < 7:
        return str(day_diff) + " days ago"
    if day_diff < 31:
        return str(int(round(day_diff / 7,0))) + " weeks ago"
    if day_diff < 365:
        return str(int(round(day_diff / 30,0))) + " months ago"
    return str(int(round(day_diff / 365))) + " years ago"


@app.route('/')
def login_registration():
    return render_template("wall_index.html")


# add AJAX to check if username is already taken!
@app.route('/check_username', methods=["POST"])
def check_username():
    found = False
    # print(request.form['username'])
    mysql = mysqlconnection.MySQLConnection("username_7")
    query = "SELECT username from accounts WHERE username = %(user)s;"
    data = { 'user': request.form['username'] }
    result = mysql.query_db(query, data)
    if result:
        found = True
    return render_template('partials/username.html', found=found)


# add AJAX to find username of the friends!
@app.route("/usersearch")
def search():
    if(len(request.args.get('username'))>=1):
        found= False
        mysql = mysqlconnection.connectToMySQL("username_7")
        query = "SELECT * FROM accounts WHERE username LIKE %%(name)s;"
        data = {
            "name" : request.args.get('username') + "%"
        }
        # print(query)
        results = mysql.query_db(query, data)
        # print(results)
        if results:
            found = True
        return render_template("partials/usersearch.html", found=found, users = results)
    else:
        return render_template("partials/usersearch.html", found=False)
        # return render_template("partials/usersearch.html", found=False, users = '')
        



@app.route('/registration', methods=["POST"])
def registration():

    email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    name_regex= re.compile(r'^[a-zA-z][a-zA-z]+$')
    password_validation = re.compile(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$')

    if (len(request.form['first_name']) < 2) and (not (name_regex.match(request.form['first_name']))):
        flash("Please enter a first name") 
    if (len(request.form['last_name']) < 2) and (not (name_regex.match(request.form['last_name']))):
        flash("Please enter a last name")
    if (len(request.form['email']) < 6) and (not (email_regex.match(request.form['email']))):
        flash("Please enter a email")
    if (len(request.form['password']) < 8) and (not (password_validation.match(request.form['password']))):
        flash("Password should be at least 8 characters and have at least 1 number and 1 uppercase letter") 
    if request.form['confirm_password'] != request.form['password']:
        flash("Comformation_password should matches password")

    if not '_flashes' in session.keys():
        mysql = mysqlconnection.MySQLConnection("username_7")
        query = "INSERT INTO accounts (username, first_name, last_name, email, password) VALUE(%(user)s, %(fn)s, %(ls)s, %(em)s, %(ps)s);"
        data={
            "user": request.form['username'],
            "fn": request.form['first_name'],
            "ls": request.form['last_name'],
            "em": request.form['email'],
            "ps": bcrypt.generate_password_hash(request.form['password']),
        }
        user_id = mysql.query_db(query, data)

        if user_id:
            print('goto login success')
            flash("You've been successfully registered")
            session['first_name'] = request.form['first_name']
            return redirect('/wall')
        else:
            flash("Something went wrong, prabably email already registered.")
            return redirect('/')
    else:
        return redirect('/') 


@app.route('/login', methods=["POST"])
def login():
    mysql = mysqlconnection.MySQLConnection("username_7")
    query = "SELECT first_name, password FROM accounts WHERE email = %(email)s;"
    data = { 'email': request.form['email']}
    
    result = mysql.query_db(query, data)
    if(len(result) == 0):
        flash('Email or password is invalid')
        return redirect ('/')
    if(bcrypt.check_password_hash(result[0]['password'], request.form['password'])):
        session['first_name'] = result[0]['first_name']
        flash("You've been log in!")
        return redirect('/wall') 
    else:
        flash('Email or password is invalid')
        return redirect('/')


@app.route('/wall')
def seccess():
    if 'first_name' in session.keys():
        data = { 'sender': session['first_name']}

        mysql = mysqlconnection.MySQLConnection("username_7")
        query = "SELECT * FROM messages WHERE receiver = %(sender)s;"
        receivedMsgs = mysql.query_db(query, data)
        for msgs in receivedMsgs:
            msgs['created_at'] = pretty_date(msgs['created_at'])

        mysql = mysqlconnection.MySQLConnection("username_7")
        query = "SELECT id FROM messages WHERE sender = %(sender)s;"
        sentMsgs = mysql.query_db(query, data)

        mysql = mysqlconnection.MySQLConnection("username_7")
        # query = "SELECT first_name FROM accounts WHERE first_name != %(sender)s ORDER BY first_name ASC;"
        query = "SELECT first_name FROM accounts WHERE first_name != %(sender)s;"
        users_first_name = mysql.query_db(query, data)
        selection_sort(users_first_name)
        return render_template('wall.html', messages_sent_count = len(sentMsgs), messages_count = len(receivedMsgs), messages = receivedMsgs,users_first_name = users_first_name)
    else:
        flash('Session expired')
        return redirect('/')


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/send_message/<sender>/<receiver>', methods=["POST"])
def send_message(sender,receiver):
    if(len(request.form['private_message']) < 5):
        flash("Content should be at least 5 characters long")
        return redirect('/wall')

    if not '_flashes' in session.keys():
        #store message into the message table
        mysql = mysqlconnection.MySQLConnection("username_7")
        query = "INSERT INTO messages (sender, receiver, message, created_at) VALUE(%(sender)s, %(receiver)s, %(message)s, NOW());"
        data={
            "sender": sender,
            "receiver": receiver,
            "message": request.form['private_message'],
        }
        users_first_name = mysql.query_db(query, data)
        return redirect('/wall')


@app.route('/remove_message/<message_id>')
def remove_message(message_id):
    mysql = mysqlconnection.MySQLConnection("username_7")
    query = "DELETE FROM messages WHERE id = %(id)s;"
    data={
        "id": message_id,
    }
    users_first_name = mysql.query_db(query, data)
    print(users_first_name)
    return redirect('/wall')


if __name__ == "__main__":
    app.run(debug=True)
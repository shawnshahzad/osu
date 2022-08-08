import json
import jwt
import datetime
import time
from os import environ as env
from re import X
from urllib.parse import quote_plus, urlencode
import urllib.parse
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, jsonify, request, make_response, redirect, render_template, session, url_for, flash
from flask_mail import Mail, Message

import requests
from werkzeug.datastructures import ImmutableMultiDict
from functools import wraps
from flask_mysqldb import MySQL

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

application = Flask(__name__)
application.config['MYSQL_HOST'] = 'localhost'
application.config['MYSQL_USER'] = 'root'
application.config['MYSQL_PASSWORD'] = ''
application.config['MYSQL_DB'] = 'db_sample'
application.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(application)

application.secret_key = env.get("APP_SECRET_KEY")

application.config['MAIL_SERVER'] = env.get("MAIL_SERVER")
application.config['MAIL_PORT'] = int(env.get("MAIL_PORT"))
application.config['MAIL_USERNAME'] = env.get("QUIZ_EMAIL")
application.config['MAIL_PASSWORD'] = env.get("MAIL_PASSWORD")
application.config['MAIL_USE_TLS'] = env.get("MAIL_USE_TLS") == 'True'
application.config['MAIL_USE_SSL'] = env.get("MAIL_USE_SSL") == 'True'
mail = Mail()
mail.init_app(application)

oauth = OAuth(application)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    # authorize_url =f'https://{env.get("AUTH0_DOMAIN")}/authorize',
    # access_token_url=f'https://{env.get("AUTH0_DOMAIN")}/oauth/token',
    # api_base_url=f'https://{env.get("AUTH0_DOMAIN")}'
    server_metadata_url = f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

#Login
def is_logged_in(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get('user')
        current_path = request.path
        quoted_path = urllib.parse.quote(current_path,safe='')
        if user:
            return f(*args, **kwargs)
        flash('Unauthorized, Please Login', 'danger')
        return redirect(url_for("login", _external=True) + '?from=' +quoted_path)
    return decorated

# # Registration
@application.route('/reg',methods=['POST','GET'])
def reg():
     status=False
     if request.method=='POST':
         name=request.form["uname"]
         email=request.form["email"]
         pwd=request.form["upass"]
         cur=mysql.connection.cursor()
         cur.execute("insert into users(UNAME,UPASS,EMAIL) values(%s,%s,%s)",(name,pwd,email))
         mysql.connection.commit()
         cur.close()
         flash('Registration Successfully. Login Here...','success')
         return redirect('login')
     return render_template("reg.html",status=status)


# Home page
@application.route("/dashboard", methods=['POST', 'GET'])
@is_logged_in
def dashboard():
    user = session["UID"]
    return render_template('dashboard.html', uid=user)


# test page
@application.route("/test", methods=['POST', 'GET'])
@is_logged_in
def test():
    if request.method == 'POST':
        result = request.form
        Table = []
        for key, value in result.items():
            temp = []
            temp.extend([key,value])
            Table.append(temp)
        q = request.form
        '''print(q)'''
        json_stuff= (q.to_dict(flat=False))
        qname = None
        for i in json_stuff.keys():
            if json_stuff[i] == ['Submit']:
                qname = i
        json_data = str(json_stuff)
        '''convert to json string double quotes'''
        json_string = json.dumps(json_data)
        '''open database connnection, add user defined quiz into database and close connection'''
        cur=mysql.connection.cursor()
        '''global variable which holds UID'''
        x = user = session["UID"]

        cur.execute("insert into quizinformation(UID,dataz, qname) values(%s,%s,%s)",(x,json_string,qname))

        mysql.connection.commit()
        cur.close()

        """to display in test.html"""
        print(json_stuff)

        #to extract the time for the quiz
        time_as_list = json_stuff['minutes']
        time_as_str = ''.join(time_as_list)
        time_no_brackets = time_as_str.strip("['']")
        quiz_time = int(time_no_brackets)

        return render_template("test.html", json_stuff = json_stuff, quiz_time=quiz_time)

    


@application.route("/new_quiz/<UID>/<qname>", methods=['POST', 'GET'])
@is_logged_in
def new_quiz(UID, qname):
    original_quiz_name = qname.replace("_", ' ')
    return render_template('home.html', qname=original_quiz_name, URL=qname)


@application.route("/quiz_name/<UID>", methods=['POST', 'GET'])
@is_logged_in
def quiz_name(UID):
    user = session["UID"]
    if request.method == "POST":
        qname = request.form['quiz_name']
        qname = qname.replace(" ", '_')
        return redirect(url_for('new_quiz', UID=user, qname=qname))
    return render_template('quiz_name.html', uid=user)


@application.route("/existing_quizzes/<UID>", methods=['POST', 'GET'])
@is_logged_in
def existing_quizzes(UID):
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()
    conv_list = []

    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)

    names = []
    URL_names = []
    for k in conv_list:
        for l in k.keys():
            if k[l] == ['Submit']:
                names.append(l)
                URL = l.replace(" ", '_')
                URL_names.append(URL)


    return render_template('existing_quizzes.html', names=names, UID = user, URL=URL_names)

@application.route("/edit_quiz/<UID>/<qname>", methods=['POST', 'GET'])
@is_logged_in
def edit_quiz(UID, qname):
    qname = qname.replace('_', ' ')
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()

    match = None
    conv_list = []
    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)

    for k in conv_list:
        for l in k.keys():
            if l == qname:
                match = k

    # Q/As are split up into R_ + question number
    question = 'R_'
    cur_question = 1
    # Breaks Questions and answers up from the dictionary to a list to
    # make processing possible back at the form
    num_questions = len(match.keys()) - 3
    num_answers_list = []
    questions = []
    answers = []
    ans_text_box_ids = []
    for i in range(num_questions):
        key = question + str(cur_question)
        question_num = 'ques_' + str(cur_question)
        num_answers_list.append(len(match[key])-1)
        questions.append([question_num, match[key][0]])
        for ans in match[key][1::]:
            answers.append(ans)
        cur_question += 1

    #Will absolutely have issues if more than 10 answers are given.
    cur_q = 1
    for j in num_answers_list:
        cur_text_box_id = 1
        for k in range(j):
            ans_text_box_ids.append('txt_' + str(cur_text_box_id) + '00' + str(cur_q))
            cur_text_box_id += 1
        cur_q += 1

    minutes = match['minutes']
    minutes[0] = int(minutes[0])
    emails = match['email']

    total_answers = sum(num_answers_list)
    return render_template('edit_quiz.html', num_questions=num_questions, num_answers_list=num_answers_list, questions=questions, ans_tbs=ans_text_box_ids, answers=answers, minutes=minutes, emails=emails, total_answers=total_answers, qname=qname, )


@application.route("/send_quizzes", methods=['POST', 'GET'])
@is_logged_in
def send_quizzes():
    user = str(session["UID"])
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM quizinformation WHERE UID = %s", user)
    data = cur.fetchall()
    print(data)
    conv_list = []

    for j in range(len(data)):
        conv = json.loads(data[j]['dataz'])
        conv = conv.replace("'", '"')
        conv2 = json.loads(conv)
        conv_list.append(conv2)

    quiz_names = []
    emails = []
    for k in conv_list:
        for l in k.keys():
            if k[l] == ['Submit']:
                quiz_names.append(l)
            if l == 'email':
              for item_idx in range(1,len(k[l])):
                emails.append(k[l][item_idx])


    return render_template('send_quizzes.html', quiz_names=quiz_names, emails=emails)

@application.route("/update", methods=['POST', 'GET'])
@is_logged_in
def update():
    if request.method == 'POST':
        result = request.form
        Table = []
        for key, value in result.items():
            temp = []
            temp.extend([key,value])
            Table.append(temp)
        q = request.form
        '''print(q)'''
        json_stuff= (q.to_dict(flat=False))
        qname = None
        for i in json_stuff.keys():
            print(i)
            if json_stuff[i] == ['Submit']:

                qname = i
        print(qname)
        json_data = str(json_stuff)
        '''convert to json string double quotes'''
        json_string = json.dumps(json_data)
        '''open database connnection, add user defined quiz into database and close connection'''
        cur=mysql.connection.cursor()
        '''global variable which holds UID'''
        x = session["UID"]

        cur.execute("UPDATE quizinformation SET dataz = %s WHERE UID = %s AND qname = %s", (json_string, x, qname))

        mysql.connection.commit()
        cur.close()

        """to display in test.html"""

        return redirect('dashboard')

@application.route("/view_results/<UID>", methods=['GET'])
@is_logged_in
def view_results(UID):
    return render_template('view_results.html')

@application.route("/help", methods=['POST', 'GET'])
@is_logged_in
def help():
    return render_template('help.html')


@application.route("/contact", methods=['POST', 'GET'])
@is_logged_in
def contact():
    return render_template('contact.html')


@application.route("/about")
@is_logged_in
def about():
    return render_template('about.html')


@application.route("/")
def home():
    user = session.get('user')
    if user:
        # print(json.dumps(user["userinfo"], sort_keys=False, indent=4))
        # return "Hello World, " + user["userinfo"]["name"] + "!"
        flash("Hello, " + user["userinfo"]["name"] + "!", 'success')
    else:
        # return "Hello World, Mrs. Anonymous!"
        flash("Hello, Mrs. Anonymous!",'success')
    return redirect('dashboard')


@application.route("/public")
def public():
    return "A public endpoint"


@application.route("/private")
@is_logged_in
def private():
    return "A private endpoint"


@application.route("/login")
def login():
    r_args = request.args
    url_from = r_args.get('from')
    if(url_from is None):
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True)
        )
    else:
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True) + '?to=' + url_from
        )


@application.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    cur = mysql.connection.cursor()
    cur.execute("select * from users where EMAIL=%s", [token['userinfo']['email']])
    data = cur.fetchone()
    global x
    if data:
        session['logged_in'] = True
        session['username'] = data["UNAME"]
        x = (data["UID"])
        session["UID"] = data["UID"]
    else:
        cur = mysql.connection.cursor()
        cur.execute("insert into users(UNAME,UPASS,EMAIL) values(%s,%s,%s)", (token['userinfo']['name'], '', token['userinfo']['email']))
        mysql.connection.commit()
        cur.execute("select * from users where EMAIL=%s", [token['userinfo']['email']])
        data = cur.fetchone()
        x = (data["UID"])
        session["UID"] = data["UID"]
        cur.close()
    r_args = request.args
    url_to = r_args.get('to')
    if url_to is None:
        return redirect("/")
    else:
        return redirect(urllib.parse.unquote(url_to))


# logout
# @application.route("/logout")
# def logout():
#     session.clear()
#     flash('You are now logged out', 'success')
#     return redirect(url_for('login'))
#
@application.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@application.route("/quiz4candidate", methods=['POST', 'GET'])
def quiz4candidate():
    if request.method == 'GET':
        r_args = request.args
        candidate_info = r_args.get('candidate_info')
        if candidate_info is None:
            return "No candidate_info!"
        else:
            try:
                candidate_info = urllib.parse.unquote(candidate_info)
                candidate_info_data = jwt.decode(candidate_info, env.get('JWT_SECRET'), algorithms=['HS256'])
            except Exception as ex:
                print(ex)
                return "Incorrect candidate"
            return jsonify(candidate_info_data)
    else:
        emails = request.form["email"].split(';')
        exp = request.form.get('exp')
        quiz_name = request.form.get('quiz_name')
        if exp is None:
            exp = 30
        else:
            exp = int(exp)
        print('Cookies\n')
        print(request.cookies)
        print('Session\n')
        print(session)
        user = session.get('user')
        if user:
            userinfo = user.get('userinfo')
            sender_name = userinfo.get('name')
        else:
            sender_name = 'Online Quiz'
        if len(emails) > 1:
            with mail.connect() as conn:
                for email in emails:
                    token = jwt.encode({'candidate_email': email,
                                        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp),
                                        'quiz_name': quiz_name},
                                       env.get("JWT_SECRET"))
                    msg = Message("Quiz Link from {}".format(sender_name), sender = env.get("QUIZ_EMAIL"), recipients = [email])
                    msg.body = url_for('quiz4candidate', _external=True) + '?candidate_info=' + urllib.parse.quote(token,safe="")
                    conn.send(msg)
                    time.sleep(60)
        else:
            token = jwt.encode({'candidate_email': emails[0],
                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=exp),
                                'quiz_name': quiz_name},
                               env.get("JWT_SECRET"))
            msg = Message("Quiz Link from {}".format(sender_name), sender = env.get("QUIZ_EMAIL"), recipients = [emails[0]])
            msg.body = url_for('quiz4candidate', _external=True) + '?candidate_info=' + urllib.parse.quote(token,safe="")
            mail.send(msg)
        return jsonify({'email': emails})



@application.route("/jwtgen", methods=['POST', 'GET'])
def jwtgen():
    if request.method == 'POST':
        email = request.form["email"]
        token = jwt.encode({'candidate_email': email,
                            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)},
                           env.get("JWT_SECRET"))
        return jsonify({'token': token,
                        'email': urllib.parse.quote(email,safe=""),
                        'to_en': urllib.parse.quote(token,safe="")})
    else:
        r_args = request.args
        email = r_args.get('email')
        # print(session)
        print(request.cookies)
        r = requests.post(url_for('quiz4candidate', _external=True), data={'email': email},cookies=request.cookies)
        # print(r.json())
        return '{:d}'.format(r.status_code)


if __name__ == '__main__':
    # app.secret_key='secret123'
    application.run(debug=True)

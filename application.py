import os
import datetime
#import OAuth2WebServerFlow

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from newsapi import NewsApiClient
from helpers import *
from sendgrid import *
import google.oauth2.credentials
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
import oauth2client


# Ensure environment variable is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# All the keys so we don't have to get it later -- IMPORTANT DO NOT SHARE KEYS
newsapi = NewsApiClient("news_api_client_here")
sg = sendgrid.SendGridAPIClient("send_grid_api_key_here")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    user = db.execute("SELECT * FROM users WHERE id = :userid", userid = session["user_id"])
    username = user[0]["username"]
    session["project_id"] = "-1"

    if request.method == "GET":
        user_projects = db.execute("SELECT * FROM projects WHERE userid = :userid", userid = session["user_id"])
        projects = []
        if user_projects == []:
            return render_template("newproject.html", welcome = 1)

        for item in user_projects:
            sources = db.execute("SELECT * FROM sources WHERE projectid = :projectid", projectid=item["projectid"])
            num_of_sources = len(sources)
            projects.append({"id": item["projectid"], "name": item["project"], "numsources": num_of_sources, "description": item["description"]})

        return render_template("index.html", projects = projects, user = username) #should be working now. I know I messed up the database at the beginning,

    if request.method == "POST":
        project = request.form.get("project_select")
        project_name = project.split(" ", 2)[2]

        if project_name == "New Project":
            return render_template("newproject.html", welcome = 0)
        else:
            project_id = db.execute("SELECT projectid FROM projects WHERE project = :name", name=project_name)
            session["project_id"] = int(project_id[0]["projectid"])
            return redirect("/project")


@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if rows[0]["verify"] == 0:
            return render_template("notverified.html")

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["project_id"] = -1

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        username = request.form.get("username")
        rawpass = request.form.get("password")
        if len(rawpass) < 6 or len(rawpass) > 20:
            return apology("Your password must have between 6 to 20 characters.", 403)
        hasnum = False
        hascap = False
        for char in rawpass:
            if char.isdigit():
                hasnum=True
            if char.isupper():
                hascap=True
        if not hasnum and not hascap:
            return apology("Your password needs to have a capital letter and a number.", 403)

        password = generate_password_hash(rawpass)
        #check password is correct
        if not rawpass == request.form.get("confirmation"):
            return apology("Passwords don't match. Sorry!", 403)

        userlist = db.execute("SELECT username FROM users")
        for user in userlist:
            if username == user["username"]:
                return apology("This username is already taken. Sorry!", 403)
        result = db.execute("SELECT id FROM users ORDER BY id DESC LIMIT 1")
        if result == []:
            result.append({"id": -1})

        token = generate_token()
        email = request.form.get("email")
        #enter user & stuff into Users table
        db.execute("INSERT INTO users VALUES (:idnumber, :username, :passwordhash, :email, :token, :verify)",
            idnumber = int(result[0]["id"]) + 1, username = request.form.get("username"), passwordhash = password, email = email,
            token = token, verify = 0)
        email_verify(email, token)
        # get highest ID
        # insert to highD + 1
        # log them in.
        session["user_id"] = int(result[0]["id"]) + 1
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/notverified", methods=["GET", "POST"])
def notverified():
    if request.method=="POST":
        if request.form.get("verifyagain"):
            email = request.form.get("email")
            email_list = db.execute("SELECT email FROM users")
            found_email = False
            for emails in email_list:
                if emails == email:
                    found_email = True
            if found_email == False:
                return apology("Yoinks! We can't find your email!", 403)
            token = db.execute("SELECT token FROM users WHERE email = :email", email = email)
            email_verify(email, token)
        return redirect("/")
    else:
        return render_template("notverified.html")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method=="POST":
        return redirect("/")

    token = request.args.get("token")
    print(token)
    users = db.execute("SELECT * FROM users WHERE token = :token", token = token)

    print(users)
    if users is not []:
        uid = users[0]["id"]
        db.execute("UPDATE users SET verify = 1 WHERE id = :id", id = uid)
        return render_template("verify.html")
    else:
        return redirect("/")

@app.route("/newproject", methods=["GET", "POST"])
@login_required
def newproject():
    if request.method=="POST":
        name = request.form.get("name")
        description = request.form.get("description")
        result = db.execute("SELECT projectid FROM projects ORDER BY projectid DESC LIMIT 1")
        if result == []:
            result.append({"id": -1})
        projectid = int(result[0]["projectid"])+1
        userid = session["user_id"]
        db.execute("INSERT INTO projects VALUES (:projectid, :userid, :projectname, :description)",
            projectid = projectid, userid = userid, projectname = name, description=description)
        session["project_id"] = projectid
        return redirect("/project")
    else:
        return render_template("newproject.html")

@app.route("/project", methods=["GET", "POST"])
@login_required
def project():
    sources = db.execute("SELECT * FROM sources WHERE projectid = :projectid", projectid = session["project_id"])
    paper = db.execute("SELECT document FROM projects WHERE projectid = :projectid", projectid = session["project_id"])
    project = db.execute("SELECT project, description FROM projects WHERE projectid = :projectid", projectid = session["project_id"])

    return render_template("project.html", sources=sources, paper=paper[0]["document"], project=project[0])

@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    if request.method == "POST":
        query = request.form.get("query")
        sort = request.form.get("sort")
        sort = sort.lower()

        if sort == "date (sorted by new)":
            sort = "publishedAt"
        #saving last query for future things
        session["last_query"] = query
        session["last_sort"] = sort
        session["last_page"] = 1
        session["source-list"] = request.form.get("source-list")
        session["source-blacklist"] = request.form.get("source-blacklist")

        if request.form.get("source-list") != "" or request.form.get("source-blacklist") != "":
            results = extended_news(query, 1, sort, request.form.get("source-list"), request.form.get("source-blacklist"))
        else:
            results = search_news(query, 1, sort)
        if results[0] == 1:
            return render_template("search.html", error = 1, error_message = results[1])
        return render_template("results.html", results = results[1], num_results = results[0], page_number=results[2], query = query)
    else:
        return render_template("search.html")

@app.route("/sources", methods=["GET", "POST"])
@login_required
def results():
    query, sort, page = session["last_query"], session["last_sort"], session["last_page"]
    sourcelist, blacklist = session["source-list"], session["source-blacklist"]
    print(page)

    if request.method=="POST":
        #intentionally separated for multiple pages:

        page_num = int(request.form.get("page_number"))
        print(page_num)
        if page_num == "" or session["last_page"]:
            session["last_page"] = session["last_page"] + 1
        else:
            session["last_page"] = page_num

        if sourcelist != "" or blacklist != "":
            results = extended_news(query, session["last_page"], sort, request.form.get("source-list"), request.form.get("source-blacklist"))
        else:
            results = search_news(query, session["last_page"], sort)
        if results[0] == 1:
            return render_template("search.html", error = 1, error_message = results[1])
        return render_template("results.html", results = results[1], num_results = results[0], page_number = results[2], query = query)
    else:
        if sourcelist != "" or blacklist != "":
            results = extended_news(query, 1, sort, request.form.get("source-list"), request.form.get("source-blacklist"))
        else:
            results = search_news(session["last_query"], 1, sort)
        if results[0] == 1:
            return render_template("search.html", error = 1, error_message = results[1])
        return render_template("results.html", results = results[1], num_results = results[0], page_number = results[2], query = query)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    article_id = int(request.args.get("article_id"))
    page_id = int(request.args.get("page_id"))
    query = session["last_query"]
    sort = session["last_sort"]
    results = search_news(session["last_query"], page_id, sort)

    if article_id >= 20:
        article_id = article_id % 20

    article = results[1][article_id]
    matching_articles = db.execute("SELECT url FROM sources WHERE url = :url AND projectid = :projectid", url = article["url"], projectid = session["project_id"])
    if matching_articles != []:
        return render_template("results.html", error=1)

    checkid = db.execute("SELECT sourceid FROM sources ORDER BY sourceid DESC LIMIT 1")
    if checkid == []:
        checkid.append({"sourceid": -1})
    today = datetime.datetime.today()

    db.execute("INSERT INTO sources VALUES (:sourceid, :projectid, :sourcename, :url, :author, :datepub, :datefound, :publisher, :annotation, :articlename)",
        sourceid = checkid[0]["sourceid"]+1, projectid = session["project_id"], sourcename = article["sitename"], url = article["url"],
        author = article["author"], datepub = article["date"], datefound = today.isoformat(), publisher = article["sitename"], annotation = "",
        articlename = article["title"])
    return redirect("/project")

@app.route("/cite", methods=["GET", "POST"])
@login_required
def cite():
    if request.method == "POST":
        source, citeformat = request.form.get("sourceselect"), request.form.get("citeformat")
        print(source)
        sourcetocite = db.execute("SELECT * FROM sources WHERE articlename = :articlename AND projectid = :projectid",
            projectid = session["project_id"], articlename = source)
        print(sourcetocite)
        article = sourcetocite[0]
        firstname, lastname = article["author"].split(" ")[0], article["author"].split(" ")[1]
        datepublist = datetime.datetime.strptime(article["datepub"], "%Y-%m-%d")
        datepub = {
            "year":datepublist.year,
            "month":datepublist.strftime("%B"),
            "day":datepublist.day}

        return render_template("citeresult.html", firstname = firstname, lastname = lastname, datepub = datepub, article = article, citeformat = citeformat)

    else:
        sources = db.execute("SELECT * FROM sources WHERE projectid = :projectid", projectid = session["project_id"])
        return render_template("cite.html", sources=sources)

    return apology(400, "TODO")

@app.route("/citeresult", methods = ["GET", "POST"])
@login_required
def citeresult():
    if request.method == "POST":
        return redirect("/cite")
    if request.method == "GET":
        return render_template("citeresult.html")

@app.route("/make", methods = ["GET", "POST"])
@login_required
def make():
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' #I'm getting an error and because I want to solve this now this is a makeshift solution
    if 'credentials' not in session:
        return redirect("/auth")
    creds = google.oauth2.credentials.Credentials(session['credentials'])
    print(creds)
    service = build('drive', 'v3', credentials=creds)
    document = db.execute("SELECT document FROM projects WHERE projectid = :projectid", projectid = session["project_id"])

    if request.method == "POST":
        db.execute("UPDATE projects SET document = :document WHERE projectid = :project_id", project_id = session["project_id"], document = None)
        return redirect("/choose")
    if document[0]["document"] is not None:
        return render_template("make.html", documentid = document[0]["document"])
    else:
        return redirect("/choose")

# literally everything in /auth and /callback are from Google because I don't like OAuth
@app.route("/auth", methods = ["GET", "POST"])
def auth():
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file('credentials.json', scopes=['https://www.googleapis.com/auth/drive.metadata.readonly'])
    flow.redirect_uri = url_for('callback', _external=True, _scheme="https")
    authorization_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true")
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback", methods = ["GET", "POST"])
def callback():
    state = session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file('credentials.json', scopes=None)
    flow.redirect_uri = url_for('callback', _external=True, _scheme="https")
  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    return redirect("/make")

@app.route("/choose", methods = ["GET", "POST"])
@login_required
def choose():
    if request.method == "POST":
        fileId = request.form["fileId"]
        db.execute("UPDATE projects SET document = :document WHERE projectid = :projectid", document = fileId, projectid = session["project_id"])
        return redirect("/make")
    else:
        if db.execute("SELECT document FROM projects WHERE projectid = :projectid", projectid = session["project_id"])[0]["document"] is not None:
            return redirect("/make")
        return render_template("choose.html")

def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

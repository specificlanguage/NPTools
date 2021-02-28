import csv
import os
import urllib.request

from flask import redirect, render_template, request, session
from functools import wraps
import sendgrid
import os
from sendgrid.helpers.mail import *
from random import randint
from newsapi import NewsApiClient

# All the keys so we don't have to get it later -- IMPORTANT DO NOT SHARE KEYS
newsapi = NewsApiClient("news_api_key_here")

def generate_token():
    token = ""
    for i in range(10):
        n = randint(0,2)
        if n == 0:
            c = randint(48, 57)
        elif n == 1:
            c = randint(65, 90)
        else:
            c = randint(97, 122)
        token += chr(c)
    return token


def email_verify(address, token):
    #everytime you boot this up, please do:
        # export SENDGRID_API_KEY="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"
        # If I'm not lazy, I'll try and get a .bat file going so we don't have to do this every single time...
    sg = sendgrid.SendGridAPIClient("sendgrid_api_key_here")
    message = Mail(from_email=From('email_here', 'Michael from NPTools'),
                to_emails=To(address, ""),
                subject=Subject('NoodlePowerTools Verification'),
                plain_text_content=PlainTextContent("Hello, click to verify. http://ide50-specificlanguage.legacy.cs50.io:8080/verify?token=" + token))

    sg.send(message)

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

#results returns this stuff: https://newsapi.org/docs/endpoints/everything
def search_news(query, page, sort, *args, **kwargs):
    results = newsapi.get_everything(q = query, language = "en", sort_by=sort, page=page)
    if results["status"] == "error":
        return [1, results["message"]]

    results_length = int(results["totalResults"])
    page_results = []

    if len(results["articles"]) < 20:
        var = len(results["articles"])
    else:
        var = 20

    for i in range(var):
        date = results["articles"][i]["publishedAt"].split("T", 1)[0]

        page_results.append({
            "search_id": i,
            "sitename": results["articles"][i]["source"]["name"],
            "author": results["articles"][i]["author"],
            "title": results["articles"][i]["title"],
            "description": results["articles"][i]["description"],
            "url": results["articles"][i]["url"],
            "date": date
            })

    full_results = [results_length, page_results, page]
    return full_results

def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def extended_news(query, page, sort, domainstosearch, domainstoblacklist):
    results = newsapi.get_everything(q = query, language = "en", sort_by=sort, page=page)
    if results["status"] == "error":
        return [1, results["message"]]

    results_length = int(results["totalResults"])
    page_results = []

    if len(results["articles"]) < 20:
        var = len(results["articles"])
    else:
        var = 20

    for i in range(var):
        date = results["articles"][i]["publishedAt"].split("T", 1)[0]

        page_results.append({
            "search_id": i,
            "sitename": results["articles"][i]["source"]["name"],
            "author": results["articles"][i]["author"],
            "title": results["articles"][i]["title"],
            "description": results["articles"][i]["description"],
            "url": results["articles"][i]["url"],
            "date": date
            })

    full_results = [results_length, page_results, page]
    return full_results

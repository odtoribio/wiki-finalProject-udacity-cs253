import re
import logging
import json
from string import letters
import os
import jinja2
import webapp2
import random
import string
import hashlib
import hmac
import urllib2
import time
"""
    def get(self, post_id):
        global username_glob
        u = WikiDB.by_urlID(post_id)
        x = self.request.cookies.get("user_id")
        id_user = check_secure_val(x)
        value = self.request.get('v')
        default = None
        if not id_user:
            self.redirect("/login")

        if value:
            if value.isdigit():
                default = WikiDB.get_by_id(int(value))
            if not value:
                return self.notfound()
        else:
            default = u.wikicontent

        self.render("edit.html", content = default, user = username_glob)
        logging.info('rendered %s', 'Edit Page')
"""

from datetime import datetime, timedelta
from google.appengine.api import memcache
from google.appengine.ext import db

### DRIVER OF LOGGIN ###
DEBUG = bool(os.environ['SERVER_SOFTWARE'].startswith('Development'))
if DEBUG:
    logging.getLogger().setLevel(logging.DEBUG)


template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape= False)


def write(self,*a,**kw):
    self.response.write(*a,**kw)

def render_str(self,template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render(self,template,**kw):
    self.write(self.render_str(template,**kw))


class MainHandler(webapp2.RequestHandler):

    username_error = ""
    password_error =""
    verify_error = ""
    email_error = ""
    name = ""
    em=""

    #VALIDATION METHODS
    def valid_username(self,username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        status = USER_RE.match(username)

        if status == None:
            self.username_error = "That's not valid Username"
            return False
        else:
            self.name = username
            return True

    def valid_email(self,email):
        email_re = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        status = email_re.match(email)

        if (status != None) or (not email):
            self.em = email
            return True
        else:
            self.email_error = "That's not valid email"
            return False

    def valid_password(self,password,verify):
        password_re = re.compile(r"^.{3,20}$")

        if not password:
            self.password_error = "That's wasn't a valid password"
            return False
        else:
            status = password_re.match(password)
            if (status != None):
                if password == verify:
                    return True
                else:
                    self.verify_error = "Your passwords didn't match"
                    return False
            else:
                self.password_error = "That's wasn't a valid password"
                return False

    # VERIFY IF USER IS NOT IN DATABASE
    def user_is_free(self,username):
        u = DB.all().filter('user =', username).get()
        if u:
            self.username_error = "User already exists."
            return False
        else:
            return True

    # PASSWORD HASH HANDLER
    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

    def make_pw_hash(self,name, pw, salt = None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (h, salt)

    def valid_pw(self,name, pw, h):
        x= h.split(',')[1]
        return h == self.make_pw_hash(name,pw,x)


    #FOR THE COOKIES

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))


    #METHODS FOR JINJA TEMPLATES

    def write(self,*a,**kw):
        self.response.write(*a,**kw)

    def render_str(self,template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self,template,**kw):
        self.write(self.render_str(template,**kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

### USER DATABASE ###
class DB(db.Model):

    user = db.StringProperty(required = True)
    hash_ps = db.StringProperty(required = True)
    email =db.StringProperty()

### WIKI DATABASE ###
class WikiDB(db.Model):

    urlID = db.StringProperty(required = True)
    wikicontent = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @classmethod
    def by_urlID(cls, urlID):
        u = WikiDB.all().filter('urlID =',urlID).get()
        return u

class EditPage(MainHandler):

    def get(self, post_id):
        global username_glob
        u = WikiDB.by_urlID(post_id)
        x = self.request.cookies.get("user_id")
        id_user = check_secure_val(x)
        logging.info('porno')
        logging.info('%s',id_user)
        logging.info('%s',post_id)
        if id_user:
            if u:
                self.render("edit.html", content = u.wikicontent , user = username_glob, link = post_id)
            else:
                self.render("edit.html", content = "", user = username_glob)
            logging.info('rendered %s', 'Edit Page')
        else:
            self.redirect("/login")

    def post(self, redir_id):
        path = self.request.path
        unquoted_path = urllib2.unquote(path)
        content = self.request.get('content')

        u = WikiDB(urlID = unquoted_path[6:], wikicontent = content)
        u.put()
        time.sleep(0.1)
        logging.info("saved in DB")
        logging.info('courrent path is %s', unquoted_path[6:])
        perLink = str(unquoted_path[6:])
        logging.info("hola 2")
        self.redirect('%s' % perLink)

class WikiPage(MainHandler):
    def get(self, post_id):
        u = WikiDB.by_urlID(post_id)
        global username_glob
        x = self.request.cookies.get("user_id")
        id_user = check_secure_val(x)
        if id_user:
            if u:
                logging.info('%s', str(post_id))
                self.render("view.html", content = u.wikicontent, id = post_id, user = username_glob)
            elif username_glob and not u:
                redir_id = '/_edit' + post_id
                self.redirect(redir_id)
                logging.info('%s', redir_id)
            else:
                self.redirect("/login")
        else:
            username_glob  = None
            if u:
                self.render("view.html", content = u.wikicontent, id = post_id, user = username_glob)
            else:
                self.redirect('/login')

### COOKIES HANDLER ###
secret = 'oscar'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

### GLOBAL VARIABLE FOR THE REGISTER OR LOGIN ###
username_glob = None


class Signup(MainHandler):

    def get(self):
        self.render("signup.html",em = self.em , name = self.name , username_error = self.username_error ,
                    password_error = self.password_error, verify_error = self.verify_error, email_error = self.email_error)

        x = self.read_secure_cookie("user_id")


    def post(self):

        #reading data and saving in the var
        user = self.request.get("username")
        password = self.request.get("password")
        email = self.request.get("email")
        hs_password = self.make_pw_hash(user,password)
        global username_glob
        username_glob = user


        # next ver returns boolean
        username = self.valid_username(self.request.get("username"))
        password_v = self.valid_password(self.request.get("password"), self.request.get("verify"))
        e_mail = self.valid_email(self.request.get("email"))
        if username and self.user_is_free(user):
            if  password_v and e_mail:
                u = DB(user = user,hash_ps = hs_password , email = email)
                u.put()
                self.login(u)
                self.redirect('/welcome')
            else:
                self.render("signup.html",em = self.em , name = self.name , username_error = self.username_error ,
                    password_error = self.password_error, verify_error = self.verify_error, email_error = self.email_error)


        else:
            self.render("signup.html",em = self.em , name = self.name , username_error = self.username_error ,
                    password_error = self.password_error, verify_error = self.verify_error, email_error = self.email_error)

class Login(MainHandler):
    def get(self):
        self.render("login.html",error = "")
        logging.info('Rendered %s', 'Login Page')
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        global username_glob
        username_glob = username
        u = DB.all().filter('user =', username).get()
        if u and self.valid_pw(username,password,u.hash_ps):
            self.set_secure_cookie('user_id', str(u.key().id()))
            self.redirect('/')
        else:
            self.render("login.html",error = "Invalid login")

class Logout(MainHandler):
    def get(self):
        global username_glob
        cookie = ""
        self.response.headers.add_header('Set-Cookie','user_id=%s; Path=/' %(cookie))
        self.redirect("/signup")
        logging.info('Rendered %s', 'Logout')
        username_glob = None

class Welcome(Signup):

    global username_glob
    def get(self):
        x = self.request.cookies.get("user_id")
        id_user = check_secure_val(x)
        if id_user and DB.get_by_id(int(id_user)):
            self.response.write("Welcome, "+ username_glob +"!")
        else:
            self.redirect('/signup')

class MainPage(MainHandler):
    def get(self):
        global username_glob
        self.render("view.html", content = "<h1> This is the Main Page</h1>" ,user = username_glob)

class History(MainHandler):
    def get(self,post_id):
        global username_glob
        path = self.request.path
        unquoted_path = urllib2.unquote(path)

        logging.info('entro a history')
        p = WikiDB.all().filter('urlID =', post_id).get()
        if p:
            h = WikiDB.all().filter('urlID =', post_id).order('-created').fetch(None)
            self.render('history.html', history = h, user= username_glob)
            logging.info('entrooooooooooooooooooooooooooooo')
        else:
            logging.info('entroooooooooooooooooooooxxxxxxxxx')
            #self.redirect('/')
            self.redirect('/_edit'+post_id)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/welcome', Welcome),
    ('/signup', Signup),
    ('/login', Login),
    ('/logout',Logout),
    ('/_history'+PAGE_RE, History),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage)

], debug=True)
#import python / GAE web app framework
import webapp2
#import templating framework
import jinja2
#import logging
import logging
#import os to manipulate file paths
import os
#imports the ranom function for making salts
import random
#import hashlib = hash library for hashing and security sha256
import hashlib
#imports the string.letters which is a string of all alphabetic characters upper and lowercase
from string import letters
#import the regex library
import re
#add GAE db support
from google.appengine.ext import db
#import library for manipulating urls
import urllib2

#import hmac= key hashed message authentication code
import hmac

secret = '*F*HEUPSCEPCB@#&TO&*@^#*@&'

#setup and configure logging
DEBUG = bool(os.environ['SERVER_SOFTWARE'].startswith('Development'))
if DEBUG:
    logging.getLogger().setLevel(logging.DEBUG)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

#create a secure value, and return both the val and the secure value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

#looks at a hashed value(cookie), and splits out the hashed value and compares the hashes
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#Create a general handler that all other handlers extend
class MainHandler(webapp2.RequestHandler):
	#simplifies writing self.response.out.write
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	#takes template name and returns a string of that content, similar to  ''' ''''
	def render_str(self, template, **params):
		#check self.user from the initialize method to see if user is logged in
		params['user'] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)
	#call write out string
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
	#login function to set the cookie
	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))
		logging.info('Set Login Cookie')
	#Logout function clears the cookie but setting user_id=''
	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
	#create a secure cookie and set it by calling the add header function
	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))
	#a function which find the cookie based on a certain value, look at the secure cookie returned and checks to make sure it is valid
	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	### initialize function called by requestHandler on page load
	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		#get the cookie user_id and return the value
		uid = self.read_secure_cookie('user_id')
		#if uid is not null and the uid is in the db, then set self.user to TRUE, else FALSE
		self.user = uid and User.by_id(int(uid))

### User Methods ###

#essential creates a group of random characters with length of 5
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	#Key.from_path(kind, id_or_name, parent=None, namespace=None)
	return db.Key.from_path('users', group)

def wiki_key(group = 'main'):
	return db.Key.from_path('wikis', group)

#create WIKIPAGE model which inherits db.model
class WikiPage(db.Model):
	urlID = db.StringProperty(required = True)
	wikicontent = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	@classmethod
	def by_urlID(cls, urlID):
		u = WikiPage.all().filter('urlID =',urlID).get()
		return u

#create USER model which inherits db.model
class User(db.Model):
	#this is actually the username
	name = db.StringProperty(required = True)
	#actual password is not stored in DB, only hash of password
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	#@classmethod bounds these functions to this class and will only perform on the data, look into more.
	#refers to actual class by calling cls, instead of refering to an instance of the class
	@classmethod
	def by_id(cls, uid):
		#get_by_id is a function from db.model
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		#lookup username from db https://developers.google.com/appengine/docs/python/datastore/queryclass
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	#takes in the form elements, and ceates a password hash, and returns items in tuple to be stored by .put()
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = cls.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u

class ViewHandler(MainHandler):
    def get(self, post_id):
        u = WikiPage.by_urlID(post_id)
        logging.info('%s', str(u))
        if u:
        	logging.info("POST IS THERE")
        	logging.info('%s', str(post_id))
        	self.render("view.html", content = u.wikicontent, id = post_id)
        elif self.user and not u:
        	redir_id = '/_edit' + post_id
        	self.redirect(redir_id)
        	logging.info('%s', redir_id)
        	logging.info("POST NO THERE BUT USER LOGGED IN")
        else:
        	logging.info("NO POST + NOT LOGGED IN")
        	self.redirect("/login")


class EditHandler(MainHandler):
	#### why does this need two? ####
    def get(self, post_id):

    	u = WikiPage.by_urlID(post_id)
    	if u:
        	self.render("edit.html", content = u.wikicontent)
        else:
        	self.render("edit.html", content = "Please enter text.")
        logging.info('rendered %s', 'Edit Page')
    def post(self, redir_id):
		path = self.request.path
		unquoted_path = urllib2.unquote(path)

		content = self.request.get('content')

		u = WikiPage(urlID = unquoted_path[6:], wikicontent = content)
		u.put()
		logging.info('%s', unquoted_path[6:])
		self.redirect('%s' % str(unquoted_path[6:]))

##front end validation of username, password, and email forms
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)

class SignupHandler(MainHandler):
    #renders the file signup-form.html from the templates folder
    def get(self):
        self.render("signup-form.html")
    #on form post, pulls in each value from the form
    def post(self):
    	have_error = False
    	self.username = self.request.get('username')
    	self.password = self.request.get('password')
    	self.verify = self.request.get('verify')
    	self.email = self.request.get('email')

    	#allows us to call one function to pass errors, if there is an error, we add a new key-value pair of the error.
    	params = dict(username = self.username,
    				  email = self.email)

    	#validations on each field
    	if not valid_username(self.username):
    		params['error_username'] = "That's not a valid username."
    		have_error = True
    	if not valid_password(self.password):
    		params['error_password'] = "That wasn't a valid password."
    		have_error = True
    	elif self.password != self.verify:
    		params['error_verify'] = "Your passwords didn't match."
    		have_error = True
    	if not valid_email(self.email):
    		params['error_email'] = "That's not a valid email."
    		have_error = True

    	#if error reload the form with the **params dict passed in which includes the original email and username entered along with the error
    	if have_error:
    		self.render('signup-form.html', **params)
    	else:
    		self.done()

    	#This exception is derived from RuntimeError. In user defined base classes, abstract methods should raise this exception
    	#when they require derived classes to override the method.
    def done(self, *a, **kw):
    	raise NotImplementedError

class Register(SignupHandler):
	def done(self):
		#make sure the user doesn't already exist
		u = User.by_name(self.username)
		#error if exists
		if u:
			msg = 'That user already exists.'
			self.render('signup-form.html', error_username = msg)
		else:
			#if not, call user.register classmethod which puts parameters into a dict, then puts dict into db
			u = User.register(self.username, self.password, self.email)
			u.put()
			#call @classmethod login
			self.login(u)
			self.redirect('/')

class LoginHandler(MainHandler):
	def get(self):
		self.render('login-form.html')
		logging.info('Rendered %s', 'Login Page')
	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username, password)
		if u:
			#calls the login function
			self.login(u)
			self.redirect('/')
			#if invalid login, reload login form with error message
		else:
			msg = 'Invalid Login'
			self.render('login-form.html', error = msg)

class LogoutHandler(MainHandler):
	def get(self):
		#calls MainHandler.logout()
		self.logout()
		self.redirect('/')
		logging.info('Rendered %s', 'Logout')

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
#url regex to handler mapper
#get matched in order
app = webapp2.WSGIApplication([
			    			 ('/signup', Register),
							 ('/login', LoginHandler),
							 ('/logout', LogoutHandler),
							 ('/_edit' + PAGE_RE, EditHandler),
    						 (PAGE_RE, ViewHandler),
    						 ],
    						 debug=True)
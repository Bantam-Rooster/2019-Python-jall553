import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import sqlite3
import socket
import Api


startHTML = "<html><head><title>Tweety</title><link rel='stylesheet' href='stylesheet.css' type='text/css' /><link rel='stylesheet' href='https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css' integrity='sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T' crossorigin='anonymous'></head><style>body{background-color: powderblue;}</style><body>"


class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True,
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "<h1><i><b>Welcome To TWATTER</b></i></h1> <br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Frontpage <a href='/signout'>Sign out</a><br/>"
            Page += "<a href='/viewBroadcast'>View Broadcasts</a><br/>"
            Page += "<a href='/viewUsers'>View Active Users</a><br/>"
            Page += "<a href='/postBroadcast'>Post Broadcast</a><br/>"
        except KeyError: #There is no username

            Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self, bad_attempt = 0):
        Page = startHTML
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0): #All inputs are strings by default
        output = int(a)+int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authenticate(username, password)
        if error == 0:
            cherrypy.session['signing_key']= makeKey(username, password)
            userlist = listUsers(username, password)
            storedata(userlist)
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session['loginserver_record'] = getLoginServerRecord(username,password)
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()

            conn = sqlite3.connect("Username.db")
            c = conn.cursor()
            c.execute('DELETE FROM users')
            conn.commit()
            conn.close()


        raise cherrypy.HTTPRedirect('/')

    @cherrypy.expose
    def viewUsers(self):

        Page = startHTML

        conn = sqlite3.connect("Username.db")
        c = conn.cursor()
        c.execute('SELECT username, ip_address from users')
        rows = c.fetchall()
        for row in rows:
            Page += row[0] + "      online<br/>"
        conn.close()

        return Page

    @cherrypy.expose
    def viewBroadcast(self):

        Page = startHTML

        conn = sqlite3.connect("Username.db")
        c = conn.cursor()
        c.execute('SELECT username, message from broadcast')
        rows = c.fetchall()
        for row in rows:
            Page += "Sender: " +row[0][:7] + "      Message: "+ row[1] + "<br/>"
        conn.close()

        return Page

    @cherrypy.expose()
    def postBroadcast(self):
        Page=startHTML
        Page += '<form action="/callBroadcast" method="post" enctype="multipart/form-data">'
        Page += 'Broadcast:<br><input type = "text" name = "message"><br><input type="submit" value="Send"/></form>'

        return Page

    @cherrypy.expose()
    def callBroadcast(self, message = None):

        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')

        signing_key = cherrypy.session.get('signing_key')
        print(message)
        loginserver_record = getLoginServerRecord(username,password)

        broadcast(username, password, loginserver_record, signing_key, message)

        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###

def authenticate(username=None, password=None):
    url = "http://cs302.kiwi.land/api/ping"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
    }

    payload = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        print(data)
        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1

def ping(username=None, password=None, pubkey = None, signature = None):
    url = "http://cs302.kiwi.land/api/ping"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey": pubkey,
        "signature": signature
    }

    payload = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        print(data)
        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1


def makeKey(username, password):
    url = "http://cs302.kiwi.land/api/add_pubkey"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    signingKey1 = signing_key

    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
        'X-signature': signature_hex_str,
    }

    payload = {
        "pubkey": pubkey_hex_str,
        "username": username,
        "signature": signature_hex_str,
    }
    payload = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
        print(data)
        report(username,password,pubkey_hex_str)
        return signingKey1
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1

def report(username, password, pubkey):
    url = "http://cs302.kiwi.land/api/report"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8',
    }

    payload = {
        'connection_location': '2',
        'connection_address': '172.23.137.29:1234',
        'incoming_pubkey': pubkey,
        'status': "online"
    }

    payload = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(url, data=payload,     headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1

def listUsers(username, password):
    url = "http://cs302.kiwi.land/api/list_users"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    try:
        req = urllib.request.Request(url, data=None,     headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        JSON_Object = json.loads(data.decode(encoding))
        returnList = JSON_Object['users']
        returnMessage = JSON_Object['response']
        response.close()
        for i in range (0,(len(returnList)-1)):
            print(returnList[i]['username'])
        return returnList
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1

def getLoginServerRecord(username, password):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    try:
        req = urllib.request.Request(url, data=None,     headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        JSON_Object = json.loads(data.decode(encoding))
        returnRecord = JSON_Object['loginserver_record']
        returnMessage = JSON_Object['response']

        if (returnMessage == 'ok'):
            return returnRecord
        else:
            return " "

        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1

def checkPubkey(username, password, pubkey):
    url = "http://cs302.kiwi.land/api/check_pubkey?pubkey=" + str(pubkey)
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
    }

    payload = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(url, data=payload,     headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1


def broadcast(username, password, loginserver_record, signing_key, message):
    List = listUsers(username,password)

    for i in range(0,len(List)-1):
        print(len(List)-1)
        print(List[i]['connection_address'])
        url = "http://"+List[i]['connection_address'] +"/api/rx_broadcast"
        ctime = str(time.time())
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }
        message_bytes = bytes(loginserver_record + message + ctime, encoding='utf-8')
        signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
        signature_hex_str = signed.signature.decode('utf-8')

        payload = {
            'loginserver_record': loginserver_record,
            'message': message,
            'sender_created_at': ctime,
            'signature': signature_hex_str,
        }
        payload = json.dumps(payload).encode()

        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req, timeout = 3)
            data = response.read()  # read the received bytes
            encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
            response.close()
            print(List[i]['connection_address'])
        except urllib.error.HTTPError as error:
            print(error.read())
        except socket.timeout:
            print("ERROR TIMEOUT")
        except ConnectionRefusedError:
            print("Error Connection Refused")
        except urllib.error.URLError:
            print("URL Error")

def ping_check(username, password):
    url = "http://172.23.6.182:8008/api/ping_check"
    ctime = str(time.time())
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))

    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "my_time": ctime,
        "connection_address": '172.23.137.29:1234',
        "connection_location": '2',
    }

    payload = json.dumps(payload).encode()

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()

        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        return 1

def storedata(userlist):

    conn = sqlite3.connect("Username.db")

    c = conn.cursor()

    #c.execute("create table users (id integer primary key autoincrement not null, username text not null, ip_address text not null)")
    for i in range(0, (len(userlist)-1)):
        c.execute("""insert into users
                     (username, ip_address)
                     values
                     (?,?)""", (userlist[i]['username'], userlist[i]['connection_address']))
        conn.commit()


    conn.close()
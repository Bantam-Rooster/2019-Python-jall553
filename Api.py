import cherrypy
import server
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import sqlite3

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

class ApiApp(object):

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

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self, **params):
        print("broadcast")
        try:
            input_data = cherrypy.request.json
            loginserver_record = input_data['loginserver_record']
            message = input_data['message']
            time = input_data['sender_created_at']
            signature = input_data['signature']
            conn = sqlite3.connect("Username.db")
            print(message)

            c = conn.cursor()

            #c.execute("create table broadcast (id integer primary key autoincrement not null, username text not null, message text not null)")

            c.execute("""insert into broadcast
                         (username, message)
                         values
                         (?,?)""", (loginserver_record, message))
            conn.commit()
            conn.close()

            output = {"response":"ok"}
        except KeyError as error:
            output = {"response":"error","message": "temp"}

        return output

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self, **params):
        print("ping_check")
        try:
            input_data = cherrypy.request.json


            output = {"response":"ok"}
        except KeyError as error:
            output = {"response":"error","message": "temp"}

        return output







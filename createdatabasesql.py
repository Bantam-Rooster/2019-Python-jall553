import sqlite3
#create database if it doesn't already exist and make a connection object
conn = sqlite3.connect("mydatabase.db")
#create a cursor object for travelling the database
cursor = conn.cursor()
###create table
cursor.execute("""create table if not exists Contacts
        (Surname text,
        Forename text,
        HomeAddress text,
        HomeNumber text,
        Email text
        primary key(Email))""")

#Prompt user to enter inputs
Surname = input('Surname: ')
Forename = input('Forename: ')
HomeAddress = input('Home Address: ')
HomeNumber = input('Home Number: ')
Email = input('Email: ')

cursor.execute(''' INSERT INTO Contacts(Surname,Forename,HomeAddress,HomeNumber,Email)
              Values(?,?,?,?,?) ''',(Surname,Forename,HomeAddress,HomeNumber,Email))

conn.commit()

#retrieve all the contents of the database
cursor.execute('SELECT * from contacts')
contactList = cursor.fetchall()

#print the contents of the database neatly using a for loop
for record in contactList:
    #record[0] returns the first column in the query (surname), record[1] returns forename column.
    print('Contact: [0], [1], [2], [3], [4]'.format(record[0],record[1],record[2],record[3],record[4]))

#close connection to the database
conn.close()

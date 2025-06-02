import sqlite3 as sql
import time
import random
import os
dbPath = "database_files\database.db" #"The_Unsecure_PWA-main\database_files\database.db"
def insertUser(username, password,secret, email):
    con = sql.connect(dbPath)
    try:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO users (username,password,secret, email) VALUES (?,?,?,?)",
            (username, password, secret, email),
        )
        con.commit()
    except Exception as e:
        con.rollback()
    finally:
        con.close()
"""def usernameExists(username):
    con = sql.connect(dbPath)
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cur.fetchone() == None:
        con.close()
        return False"""

def usernameExists(username):
    con = sql.connect(dbPath)
    try:
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cur.fetchone() == None:
            con.close()
            return False
    finally:
        con.close()
    
def retrieveUserPassword(username):
    try:
        with sql.connect(dbPath) as con:
            cur = con.cursor()
            cur.execute("SELECT password FROM users WHERE username = ?", (username,))
            result = cur.fetchone()
            if result == None:
                return False
            return result[0]  # the stored password
    except Exception as e:
        print("Database error:", e)
        return False
def retrieveUserSecret(username):
    try:
        with sql.connect(dbPath) as con:
            cur = con.cursor()
            cur.execute("SELECT secret FROM users WHERE username = ?", (username,))
            result = cur.fetchone()
            if result == None:
                return False
            return result[0]  # the stored password
    except Exception as e:
        print("Database error:", e)
        return False

def listFeedback():
    print(dbPath)
    con = sql.connect(dbPath)
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    print(data)
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    f.write("")
    for row in data:
        f.write("<p>\n")
        f.write(f"{row[1]}\n")
        f.write("</p>\n")
    f.close()

def InsertComment(feedback, username):
    con = sql.connect(dbPath)
    try:
        cur = con.cursor()
        cur.execute("INSERT INTO feedback (feedback,Username) VALUES (?,?)", (feedback, username))
        con.commit()
        return True
    except Exception as e:
        con.rollback()
        return False  
    finally:
        con.close()     
def GetComments():
    with sql.connect(dbPath) as con:
        con.row_factory = sql.Row  # Enables dict-like access
        cur = con.cursor()
        comments = cur.execute(
            "SELECT id, feedback, Username as username FROM feedback"
        ).fetchall()
    return comments

def DeleteComment(id, username):
    con = sql.connect(dbPath)
    try:
        cur = con.cursor()

        cur.execute("SELECT username FROM feedback WHERE id = ?", (id,))
        comment = cur.fetchone()

        if comment and comment[0] == username: 
            cur.execute("DELETE FROM feedback WHERE id = ?", (id,))
            con.commit()  
            return True
        else:
            print("You are not authorized to delete this comment.")
            return False

    except Exception as e:
        con.rollback() 
        print(f"Error: {e}")  
        return False

    finally:
        con.close()  # Ensure the connection is closed

def EditComment(id, new_feedback, username):
    con = sql.connect(dbPath)
    try:
        cur = con.cursor()

        # Fetch the username of the comment to ensure the current user is authorized to edit it
        cur.execute("SELECT username FROM feedback WHERE id = ?", (id,))
        comment = cur.fetchone()

        if comment and comment[0] == username:  # Check if the username matches
            # If the user matches, update the comment with the new feedback
            cur.execute("UPDATE feedback SET feedback = ? WHERE id = ?", (new_feedback, id))
            con.commit()  # Apply the changes
            return True  # Successful edit
        else:
            print("You are not authorized to edit this comment.")
            return False  # Not authorized to edit

    except Exception as e:
        con.rollback()  # Rollback in case of an error
        print(f"Error: {e}")  # Optionally print the error for debugging
        return False  # Indicate failure in case of error

    finally:
        con.close()  # Ensure the connection is closed
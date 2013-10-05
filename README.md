auth_sinatra
============

== Authentication [from scratch] with Sinatra

This is an authorization test site that I built while learning about Sinatra. I did not tested it and I don't take any responsability about its relaiability. Use with care.

If you have any questions or suggestions about improvement please leave a comment.

Characteristics:

The normal sign Up procedure is based on email/password authentication. The email need to be unique in the database.
It is possible to login using other providers. I included Facebook and Twitter but it is simple to add any other, in Omniauth has the. For this I used the Omniauth library (www.omniauth.org).
It sends a message for email confirmation. The user would need to click on the link that is sent to confirm the email. The smtp user name and password are stored in the environment variables. Execute these lines from shell before running the script.

* export SMTP_USER_NAME = username
* export SMTP_PASSWORD = password

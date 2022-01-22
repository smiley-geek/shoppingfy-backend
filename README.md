# Welcome to my AUTH ROUTES

### The repo basically offers authentication\*/authorization using passport js

> - Authentication is implemented using jwts
> - The following strategies are implemented

> > - passport-google
> > - passport-jwt
> >   > 1.  Login with email and password
> >   > 2.  Forgot passport option
> >   > 3.  send otp for password resetting

> A jwt is issued after successful authentication with all strategies thus authorization does not require db

## To run the application

> > 1.  Add the following to env file
> >     > 1. DB_STRING
> >     > 2. GOOGLE_CLIENT_SECRET
> >     > 3. GOOGLE_CLIENT_ID
> >     > 4. COOKIE_SECRET
> >     > 5. SMTP_SERVER
> >     > 6. SMTP_PORT
> >     > 5. SMTP_LOGIN
> >     > 5. SMTP_PASSWORD

> > 2.  Add appropriate callback_urls in the respective files
> > 3.  Navigate to app/auth/ and run node createKey.js to create the public and private keys
> > 4.  Go to topmost directory and run npm start/node index.js

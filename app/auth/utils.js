const crypto = require("crypto");
const jsonwebtoken = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const passport = require("passport");
const dev = process.env.NODE_ENV !== "production";
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");

dotenv.config();
const pathToJwtKey = path.join(__dirname, "id_rsa_jwt_priv.pem");
const pathToPrivRefreshJwtKey = path.join(
  __dirname,
  "id_rsa_refreshJwt_priv.pem"
);
const pathToPubRefreshJwtKey = path.join(
  __dirname,
  "id_rsa_refreshJwt_pub.pem"
);

const PRIV_JWT_KEY = fs.readFileSync(pathToJwtKey, "utf8");
const PRIV_REFRESHJWT_KEY = fs.readFileSync(pathToPrivRefreshJwtKey, "utf8");
const PUB_REFRESHJWT_KEY = fs.readFileSync(pathToPubRefreshJwtKey, "utf8");

const genPassword = (password) => {
  const salt = crypto.randomBytes(32).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return { salt, hash };
};

const validPassword = (password, hash, salt) => {
  const hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return hash === hashVerify;
};
const issueJWT = (id) => {
  const expiresIn = "1h";
  const payload = {
    sub: id,
    iat: Date.now(),
  };
  const token = jsonwebtoken.sign(payload, PRIV_JWT_KEY, {
    expiresIn,
    algorithm: "RS256",
  });
  return token;
};

const issueRefreshToken = (id) => {
  const payload = {
    sub: id,
    iat: Date.now(),
  };
  const expiresIn = "10d";
  const refreshToken = jsonwebtoken.sign(payload, PRIV_REFRESHJWT_KEY, {
    expiresIn,
    algorithm: "RS256",
  });
  return refreshToken;
};

const verifyRefreshJwt = (token) => {
  return jsonwebtoken.verify(token, PUB_REFRESHJWT_KEY);
};

COOKIE_OPTIONS = {
  httpOnly: true,
  secure: !dev,
  signed: true,
  maxAge: 1000 * 60 * 60 * 24 * 10,
  sameSite: "none",
};
const verifyUser = passport.authenticate("jwt", { session: false });

// ---sending emails---
const smtpTransport = nodemailer.createTransport({
  host: process.env.SMTP_SERVER,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_LOGIN,
    pass: process.env.SMTP_PASSWORD,
  },
});

const passwordReset = async (email, token) => {
  let message = {
    from: "Shoppingfy <example@nodemailer.com>",
    to: email,
    subject: "Password reset",
    text: `If you are getting this email, you sent a forgot password request to shoppingfy. Follow this link to reset your password: <a href=http://localhost:3000/password-reset?token=${token}>Click here </a>. If not, kindly ignore it`,
    html: `If you are getting this email, you sent a forgot password request to shoppingfy. Follow this link to reset your password: <a href=http://localhost:3000/password-reset?token=${token}>Click here </a>. If not kindly ignore it</p>`,
    amp: `<!doctype html>
    <html ⚡4email>
      <head>
        <meta charset="utf-8">
        <style amp4email-boilerplate>body{visibility:hidden}</style>
        <script async src="https://cdn.ampproject.org/v0.js"></script>
        <script async custom-element="amp-anim" src="https://cdn.ampproject.org/v0/amp-anim-0.1.js"></script>
      </head>
      <body>
<h1>Hi ${email}</h1>
<p>You sent a forgot password request to shoppingfy. </p>
<p>Follow this link to reset your password:</p>  <a href=http://localhost:3000/password-reset?token=${token}>Click here </a>. <p>If not kindly ignore it</p>
      </body>
    </html>`,
  };

  const sendResult = await smtpTransport.sendMail(message);
  return sendResult;
};

module.exports = {
  genPassword,
  validPassword,
  issueJWT,
  verifyUser,
  verifyRefreshJwt,

  COOKIE_OPTIONS,
  issueRefreshToken,
  passwordReset,
};

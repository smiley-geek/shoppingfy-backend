const crypto = require("crypto");
const jsonwebtoken = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");
const passport = require("passport");
const dev = process.env.NODE_ENV !== "production";

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

module.exports = {
  genPassword,
  validPassword,
  issueJWT,
  verifyUser,
  verifyRefreshJwt,
  COOKIE_OPTIONS,
  issueRefreshToken,
};

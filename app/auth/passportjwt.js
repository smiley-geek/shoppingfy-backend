const fs = require("fs");
const path = require("path");
const User = require("../users/index").User;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJWT = require("passport-jwt").ExtractJwt;

const pathToKey = path.join(__dirname, "id_rsa_jwt_pub.pem");
const JWT_PUB_KEY = fs.readFileSync(pathToKey, "utf8");

const options = {
  jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_PUB_KEY,
  algorithms: ["RS256"],
};

const strategy = new JwtStrategy(options, async (payload, done) => {
  try {
    const user = await User.findOne({ _id: payload.sub });
    if (user) return done(null, user);
    return done(null, false);
  } catch (error) {
    done(error, null);
  }
});

module.exports = (passport) => {
  passport.use(strategy);
};

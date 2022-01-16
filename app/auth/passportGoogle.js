const { User } = require("../users/index");
const dotenv = require("dotenv");
const GoogleTokenStrategy = require("passport-google-token").Strategy;

dotenv.config();
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const options = {
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
};

const strategy = new GoogleTokenStrategy(
  options,
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ "googleProvider.id": profile.id });
      if (user) return done(null, user);

      user = await User.findOneAndUpdate(
        { email: profile.emails[0].value },
        {
          fullName: profile.displayName,
          email: profile.emails[0].value,

          googleProvider: {
            id: profile.id,
            token: accessToken,
          },
        },
        {
          upsert: true,
          new: true,
        }
      );

      return done(null, user);
    } catch (error) {
      return done(error, null);
    }
  }
);

module.exports = (passport) => {
  passport.use(strategy);
};

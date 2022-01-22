const router = require("express").Router();
const {
  validPassword,
  genPassword,
  passwordReset,
  issueJWT,

  verifyRefreshJwt,
  verifyUser,
  COOKIE_OPTIONS,
  issueRefreshToken,
} = require("./utils");
const { User } = require("../users/index");
const crypto = require("crypto");
const PasswordReset = require("./models");
const passport = require("passport");

//---email---
router.post("/register", async (req, res, next) => {
  const saltHash = genPassword(req.body.password);
  const salt = saltHash.salt;
  const hash = saltHash.hash;

  try {
    let user = await User.findOne({
      email: req.body.email,
    }).select("+password");

    if (user) {
      if (user.password._id && user.password.hash) {
        return res.json({
          success: false,
          message: "User with this email already exists",
        });
      } else {
        const updatedUser = await User.findOneAndUpdate(
          {
            email: req.body.email,
          },
          {
            password: {
              hash,
              salt,
            },
          },
          { new: true }
        );
        return res.status(201).json({ success: true });
      }
    }

    const newUser = new User({
      email: req.body.email,
      password: {
        hash,
        salt,
      },
    });
    await newUser.save();

    return res.status(201).json({ success: true });
  } catch (error) {
    return res.status(500).json(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    let user = await User.findOne({
      email: req.body.email,
    })
      .select("+password")
      .select("+refreshToken");

    if (!user)
      return res
        .status(401)
        .json({ success: false, message: "User not found" });

    if (!(user.password && user.password.hash)) {
      return res.status(401).json({
        success: false,
        message: "Please register with email and password or use google",
      });
    }

    const isValid = validPassword(
      req.body.password,
      user.password.hash,
      user.password.salt
    );

    if (!isValid)
      return res
        .status(401)
        .json({ success: false, message: "Check your email or password" });

    const token = issueJWT(user._id);
    const refreshToken = issueRefreshToken(user._id);

    user = await User.findOneAndUpdate(
      { email: req.body.email },
      { refreshToken },
      { new: true }
    );

    res.cookie("refreshToken", refreshToken, COOKIE_OPTIONS);
    return res.status(200).json({ success: true, user, token });
  } catch (error) {
    console.log(error);
    res.status(500).json(error);
  }
});

//---password reset---
//---forgot password ---> send email with a magiclink then a reset route---
router.post("/forgot-password", async (req, res, next) => {
  try {
    const email = req.body.email;
    let user = await User.findOne({ email });
    if (!user)
      return res.json({ success: false, message: "User does not exist" });
    const token = crypto.randomBytes(32).toString("hex");
    const expiresIn = Date.now() + 1000 * 60 * 30;
    user = await User.findOneAndUpdate(
      { email },
      {
        otp: { token, expiresIn },
      }
    ).select("+otp");

    //send email
    const output = await passwordReset(email, token);

    const passReset = new PasswordReset({
      email,
      response: JSON.stringify(output),
    });
    await passReset.save();
    res.json({ success: true });
  } catch (error) {
    console.log(error);
  }
});

//---password-reset---
router.post("/password-reset", async (req, res) => {
  //verify token
  const password = req.body.password;
  const token = req.body.token;
  const email = req.body.email;
  //get email and new password and create
  const saltHash = genPassword(password);
  const salt = saltHash.salt;
  const hash = saltHash.hash;
  //update current email record
  try {
    let user = await User.findOne({ email }).select("+otp");
    if (!user)
      return res
        .status(403)
        .json({ success: false, message: "This user doesn't exist" });

    if (user.otp.token !== token) {
      return res.status(403).json({
        success: false,
        message: "Your token is incorrect",
      });
    }
    if (user.otp.expiresIn < Date.now()) {
      return res.status(403).json({
        success: false,
        message: "Sorry but token has expired try again",
      });
    }

    user = await User.findOneAndUpdate(
      { email: req.body.email },
      {
        password: { salt, hash },
        otp: {
          token: "",
          expiresIn: 0,
        },
      },
      { new: true }
    )
      .select("+otp")
      .select("+password");

    return res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json(error);
  }
});

//---google---

router.post(
  "/google",
  passport.authenticate("google-token", {
    session: false,
  }),
  async (req, res) => {
    if (!req.user) {
      return res
        .status(401)
        .json({ success: false, message: "An error occured" });
    }
    try {
      let user = await User.findOne({ email: req.user.email });

      const token = issueJWT(user._id);
      const refreshToken = issueRefreshToken(user._id);

      user = await User.findOneAndUpdate(
        { email: req.user.email },
        { refreshToken },
        { new: true }
      );

      return res
        .cookie("refreshToken", refreshToken, COOKIE_OPTIONS)
        .status(200)
        .json({ success: true, user: req.user, token });
    } catch (error) {
      res.json(error);
    }
  }
);

//---refresh-token---
router.post("/refreshToken", async (req, res) => {
  const { refreshToken } = req.signedCookies;

  try {
    if (!refreshToken) {
      res.status(401).json({ success: false, message: "unauthorized" });
    }
    if (refreshToken) {
      const payload = verifyRefreshJwt(refreshToken);
      let user = await User.findById(payload.sub).select("+refreshToken");
      if (refreshToken !== user.refreshToken) {
        res.status(401).json({ success: false, message: "unauthorized" });
      }
      const token = issueJWT(user._id);
      const newRefreshToken = issueRefreshToken(user._id);
      user = await User.findOneAndUpdate(
        { email: req.body.email },
        { refreshToken },
        { new: true }
      );

      res.cookie("refreshToken", newRefreshToken, COOKIE_OPTIONS);
      res.status(201).json({ success: true, token });
    }
  } catch (error) {
    res.status(500).json(error);
  }
});

router.get("/logout", verifyUser, async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { refreshToken: "" },
      { new: true }
    ).select("+refreshToken");

    res.clearCookie("refreshToken", COOKIE_OPTIONS);
    res.status(200).json({ success: true });
  } catch (error) {
    res.status(500).json(error);
  }
});

module.exports = router;

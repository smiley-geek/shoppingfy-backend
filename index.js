const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const dotenv = require("dotenv");
const passport = require("passport");
const authRoute = require("./app/auth/routes");
const logger = require("morgan");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const path = require("path");

//basic config
const PORT = process.env.PORT || 5000;
dotenv.config();
require("./config/database");
const corsOptions = {
  credentials: true,
  origin: true,
  ///..other options
};
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, "access.log"),
  { flags: "a" }
);

const app = express();
app.use(logger("combined", { stream: accessLogStream }));
app.use(cors());
app.use(helmet());
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET));

// ---passport---
require("./app/auth/passportjwt")(passport);
require("./app/auth/passportGoogle")(passport);
app.use(passport.initialize());

// ---Routes---
app.use("/api/auth", authRoute);



app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});

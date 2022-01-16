const dotenv = require("dotenv");
const mongoose = require("mongoose");

dotenv.config();

const DB_STRING = process.env.DB_STRING.toString();

const options = {
  useUnifiedTopology: true,

  useNewUrlParser: true,
};

const connection = mongoose.connect(DB_STRING, options, (err) => {
  if (err) return console.log(err);
  console.log("connected to db");
});

module.exports = connection;

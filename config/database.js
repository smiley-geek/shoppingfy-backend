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
/*GOOGLE_CLIENT_ID=915138254141-plku2l4sl310rfbsng8gcb5epo0i3pjg.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=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
DB_STRING=mongodb://localhost:27017/shoppingfy
COOKIE_SECRET=c7d67d15473641dbc96751b0a233f42f
SMTP_SERVER=smtp-relay.sendinblue.com
SMTP_PORT=587
SMTP_LOGIN=kariukigeorge2030@gmail.com
SMTP_PASSWORD=Mvm36NEwTDapK8zc*/

module.exports = connection;

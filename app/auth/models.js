const mongoose = require("mongoose");

const passwordResetSchema = mongoose.Schema(
  {
    email: String,
    response: String,
  },
  { timeStamps: true }
);

module.exports = mongoose.model("PasswordReset", passwordResetSchema);

const mongoose = require("mongoose");

const userSchema = mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      match: /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
    },
    password: {
      type: {
        hash: String,
        salt: String,
      },
      select: false,
    },

    fullName: String,
    googleProvider: {
      type: {
        id: String,
        token: String,
      },
      select: false,
    },
    refreshToken: {
      type: String,
      default: "",

      select: false,
    },
    otp: {
      type: {
        token: String,
        expiresIn: Number,
      },
      select: false,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("User", userSchema);

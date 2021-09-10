const express = require("express");
const formidable = require("express-formidable");
const mongoose = require("mongoose");
const uid2 = require("uid2");
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");
require("dotenv").config();
const cors = require("cors");

const app = express();
app.use(formidable());
app.use(cors());

mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to DB"))
  .catch((err) => console.log(err));

const User = mongoose.model("User", {
  email: {
    unique: true,
    type: String,
  },
  username: {
    required: true,
    type: String,
  },
  token: String,
  hash: String,
  salt: String,
});

app.post("/signup", async (req, res) => {
  try {
    const { email, username, password } = req.fields;
    const user = await User.findOne({ email: email });
    if (user) {
      res
        .status(409)
        .json({ message: "Cet email est déjà associé à un compte." });
    } else {
      const salt = uid2(16);
      const hash = SHA256(password + salt).toString(encBase64);
      const token = uid2(16);

      const newUser = await new User({
        email: email,
        username: username,
        token: token,
        hash: hash,
        salt: salt,
      });

      await newUser.save();
      res.status(200).json({
        email: newUser.email,
        token: newUser.token,
      });
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.fields.email });

    if (user !== null) {
      const newHash = SHA256(req.fields.password + user.salt).toString(
        encBase64
      );
      if (user.hash === newHash) {
        res.status(200).json({
          message: `Bienvenue ${user.username} !`,
          token: user.token,
        });
      } else {
        res.status(400).json({ message: "Identifiants incorrects." });
      }
    } else {
      res.status(400).json({ message: "Identifiants incorrects." });
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

app.all("*", (req, res) => {
  res.status(400).json({ message: "Page not found" });
});

app.listen(process.env.PORT || 3000, () => {
  console.log("Server has started");
});

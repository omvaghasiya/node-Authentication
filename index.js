import express from "express";
import mongoose from "mongoose";
import path from "path";
import ejs from "ejs";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "authentication",
  })
  .then(() => console.log("Database Connected"))
  .catch((e) => console.log(e));

const authSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const Auth = mongoose.model("Auth", authSchema);

const app = express();

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set("view engine", "ejs");

const isAutenticated = async (req, res, next) => {

  const { token } = req.cookies;

  if (token) {
    const decoded = jwt.verify(token, "bhenchodBhaiAaTo");
    // console.log(decoded);

    req.user = await Auth.findById(decoded._id);
    next();
  } else {
    res.redirect("/login");
  }
};

app.get("/", isAutenticated, (req, res) => {
  // console.log(req.cookies.token);
  //   const { token } = req.cookies;
  //   if (token) {
  //     res.render("logout");
  //   } else {
  //     res.render("login");
  //   }

  //   console.log(req.user);
  res.render("logout", { name: req.user.name });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/login", async (req, res) => {
  
    const { name, email, password } = req.body;

  let user = await Auth.findOne({ email });

  if (!user) return res.redirect("/register");

//   const isMatch = user.password === password;

const isMatch = await bcrypt.compare(password,user.password);

  if (!isMatch) return res.render("login", { email, message: "incorrect password" });
  
  const token = jwt.sign({ _id: user._id }, "bhenchodBhaiAaTo");
  // console.log(token);

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");

});

app.post("/register", async (req, res) => {
  // console.log(req.body);

  const { name, email, password } = req.body;

  let user = await Auth.findOne({ email });

  if (user) {
    return res.redirect("/login");
  }

  const hashedPassword = await bcrypt.hash(password,10);

  user = await Auth.create({
    name,
    email,
    password : hashedPassword,
  });

  const token = jwt.sign({ _id: user._id }, "bhenchodBhaiAaTo");
  // console.log(token);

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});

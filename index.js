require("./utils.js");
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const { ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

//Expires after 1 hour (hour * minutes * seconds * milliseconds)
const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("403", { error: "This clearance is above your paygrade." });
    return;
  } else {
    next();
  }
}

app.get("/", (req, res) => {
  if (req.session.email) {
    
    res.render("members", {
      images: images,
      email: req.session.email,
    });
  } else {
    res.render("index");
  }
});

app.get("/members", function (req, res) {
  if (req.session.name) {
    res.render("members", {
      images: images,
      name: req.session.name
    });
  } else {
    res.redirect("/");
  }
});

app.post("/members", async (req, res) => {
  const email = req.session.email;
  res.render("members", { email: email, images: images });
});

app.get("/nosql-injection", async (req, res) => {
  var name = req.query.user;

  if (!name) {
    res.send(
      `<h3>No user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + name);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(name);

  // If we didn't use Joi to validate and check for a valid URL parameter below
  // we could run our userCollection.find and it would be possible to attack.
  // A URL parameter of user[$ne]=name would get executed as a MongoDB command
  // and may result in revealing information about all users or a successful
  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ name: name })
    .project({ name: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${name}</h1>`);
});

app.get("/createUser", (req, res) => {
  res.render("createUser");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/submitUser", async (req, res) => {
  var name = req.body.name;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object({
    name: Joi.string().alphanum().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, name, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.render("errorMessage", { error: `${validationResult.error.message}`});
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    email: email,
    password: hashedPassword,
    user_type: "user",
  });
  console.log("Inserted user");
  req.session.authenticated = true;
  req.session.name = name;
  res.redirect("/members");
});

app.post("/loggingin", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().max(20).required(),
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
      console.log(validationResult.error);
      var errorMessage = validationResult.error.details[0].message;
      res.send(
        `${errorMessage}. Please <a href="/login">try again!</a>.`
      );
      return;
    }

    const user = await userCollection.findOne({ email: email });

    if (!user) {
      res.send(
        "Invalid email or password. Please <a href='/login'>try again</a>."
      );
      return;
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      res.send(
        "Invalid email or password. Please <a href='/login'>try again</a>."
      );
      return;
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.user_type = user.user_type;
    console.log(
      req.session.name,
      req.session.user_type);
    res.redirect("/members");
  });


app.get("/logout", function (req, res) {
  req.session.destroy(function (err) {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});

const images = [
  "cat1.gif",
  "cat2.gif",
  "cat3.jpeg",
];

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const result = await userCollection
    .find()
    .project({ name: 1, _id: 1, user_type: 1 })
    .toArray();

  res.render("admin", { names: result });
});

app.post("/admin/promote", async (req, res) => {
  const { userId } = req.body;
  await userCollection.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { user_type: "admin" } }
  );
  res.redirect("/admin");
});

app.post("/admin/demote", async (req, res) => {
  const { userId } = req.body;
  await userCollection.updateOne(
    { _id: new ObjectId(userId) },
    { $set: { user_type: "user" } }
  );
  res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Assignment 2 listening on port " + port + "!");
});

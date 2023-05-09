require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const { ObjectId } = require('mongodb');



const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
let ejs = require('ejs');
const { Admin } = require("mongodb");
app.set('view engine', 'ejs');

const expireTime = 1 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
});

app.use(session({
  secret: node_session_secret,
  store: mongoStore, //default is memory store 
  saveUninitialized: false,
  resave: false

}

));
app.get('/nosql-injection', async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  // login without knowing the correct password.
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
    return;
  }

  const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});



app.get('/', (req, res) => {
res.render('index');
});


app.get('/createUser', (req, res) => {
  res.render('createUser');
});



app.get('/login', (req, res) => {

  req.session.loginError = true;
  res.render('login', {loginError: req.session.loginError});
});



app.post('/submitUser', async (req, res) => {
  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;

  const schema = Joi.object(
    {
      username: Joi.string().alphanum().max(20).required(),
      password: Joi.string().max(20).required(),
      email: Joi.string().email().required()
    });

  const validationResult = schema.validate({ username, password, email });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/createUser");
    return;
  }

  var hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ username: username, password: hashedPassword , email: email, type: "user"});
  console.log("Inserted user");
  req.session.authenticated = true;
  req.session.username = username;
  res.redirect("/members");
});


app.post('/loggingin', async (req, res) => {
  var password = req.body.password;
  var email = req.body.email;
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }


  const result = await userCollection.find({ email: email }).project({ username: 1, password: 1, email:1, _id: 1, type:1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    req.session.loginError = true;
    console.log("user not found");
    res.redirect("/login");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.cookie.maxAge = expireTime;

    // if (result[0].type === "admin") {
    //   res.redirect("/admin");
    // } else {
      res.redirect("/members");
    // }
  }
  else {
    console.log("incorrect password");
    req.session.loginError = false;
    res.render('login', {loginError: req.session.loginError});
    return;
  }
});


app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.send('<script>alert("You are not logged in to access this page."); window.location.href = "login";</script>');
  }else{
  res.render('members', {username: req.session.username});
  }
});



app.get('/admin', async (req, res) => {
  const result = await userCollection.find({ username: req.session.username }).project({ username: 1, type: 1 }).toArray();
  if (!req.session.authenticated) {
    res.send('<script>alert("You are not logged in to access this page."); window.location.href = "login";</script>');
  }
  
  else if (req.session.authenticated === true && result[0].type === "user") {
    res.send('<script>alert("Error 403 - Forbidden. You do not have permission to access this page."); window.location.href = "members";</script>');
  }

  else{
  const result = await userCollection.find({}).project({ username: 1, type:1 }).toArray();
  console.log(result); 
  res.render('admin', { users: result, user_name: req.session.username });
  }
});



app.post('/demoteUser', async (req, res) => {
  console.log("demoteUser");
  const userId = req.body.userId;
  const updateOne = await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { type: 'user' } });
const result = await userCollection.find({}).project({ username: 1, type: 1 }).toArray();
res.redirect("/admin")
});



app.post('/promoteUser', async (req, res) => {
  const userId = req.body.userId;
  const updateOne = await userCollection.updateOne({ _id: new ObjectId(userId) }, { $set: { type: 'admin' } });
  const result = await userCollection.find({}).project({ username: 1, type: 1 }).toArray();
  res.redirect("/admin")
});

app.post('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});



app.use(express.static(__dirname + "/public"));



app.get("*", (req, res) => {
  res.status(404);
  res.render('404');
})



app.listen(port, () => {
  console.log("Node application listening on port " + port);
});
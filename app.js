require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const app = express();
const mongoose = require("mongoose");
const { log } = require("console");
const encrypt = require("mongoose-encryption");
var session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: "Our little secret.", //to encrypt session data
    resave: false, //true=save session every request, false=optimize perfromance & save when needed
    saveUninitialized: false, //true=create session for every user, false=session for initialized
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.set("strictQuery", false);
mongoose.connect(process.env.MONGO_URL, { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
});

const secretSchema = new mongoose.Schema({
  text: String,
});

const Secret = mongoose.model("Secret", secretSchema);

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.LIVE_URL}/auth/google/secrets`,
      userProfileURL: process.env.GOOGLE_USER_PROFILE_URL,
      profileFields: ["id", "emails", "name"],
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { username: profile._json.email, googleId: profile.id },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: `${LIVE_URL}/auth/facebook/callback`,
      profileFields: ["id", "emails", "name"],
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { username: profile._json.email },
        {
          facebookId: profile.id,
          username: profile._json.email,
        },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get(
  "/auth/facebook",
  passport.authenticate("facebook", {
    scope: ["public_profile", "email"],
  })
);

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/secrets", function (req, res) {
  if (req.isAuthenticated()) {
    Secret.find(function (err, foundSecrets) {
      if (!err) {
        res.render("secrets", { foundSecrets: foundSecrets });
      }
    });
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      log(err);
    } else {
      res.redirect("/");
    }
  });
});

app.post("/register", function (req, res) {
  User.findOne({ username: req.body.username }, function (err, foundUser) {
    if (foundUser) {
      res.send("User was created before!");
    } else {
      User.register(
        { username: req.body.username },
        req.body.password,
        function (err, user) {
          if (err) {
            log(err);
            res.redirect("/register");
          } else {
            passport.authenticate("local")(req, res, function () {
              res.redirect("/secrets");
            });
          }
        }
      );
    }
  });
});

app.post("/login", function (req, res) {
  const username = req.body.username;
  const password = req.body.password;

  const user = new User({
    username: username,
    password: password,
  });

  req.login(user, function (err) {
    if (err) {
      log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", function (req, res) {
  const insertedSecret = req.body.secret;
  const secret = new Secret({ text: insertedSecret });
  secret.save(function (err) {
    if (!err) {
      res.redirect("secrets");
    } else {
      console.log(err);
      res.redirect("submit");
    }
  });
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});

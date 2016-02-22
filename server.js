//express setup
var express = require('express');
var app = express();
var port = 3000;

//database setup
var Sequelize = require('sequelize');
var connection = new Sequelize('my_class_app_db', 'root');
var mysql = require('mysql');
var bcrypt = require("bcryptjs");

//requiring passport
var passport = require('passport');
var passportLocal = require('passport-local');

//body parsing middleware
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({
    extended: false
}));

//handlebars setup
var expressHandlebars = require('express-handlebars');
app.engine('handlebars', expressHandlebars({
    defaultLayout: 'main'
}));
app.set('view engine', 'handlebars');


//creates a secret
app.use(require('express-session')({
    secret: 'crackalackin',
    resave: true,
    saveUninitialized: true,
    cookie : { secure : false, maxAge : (4 * 60 * 60 * 1000) }, // 4 hours
}));


//Initializing passport
app.use(passport.initialize());
app.use(passport.session());

//passport use method as callback when being authenticated
passport.use(new passportLocal.Strategy(function(username, password, done) {
    //check password in db
    User.findOne({
        where: {
            username: username
        }
    }).then(function(user) {
        //check password against hash
        if(user){
            bcrypt.compare(password, user.dataValues.password, function(err, user) {
                if (user) {
                  //if password is correct authenticate the user with cookie
                  done(null, { id: username, username: username });
                } else{
                  done(null, null);
                }
            });
        } else {
            done(null, null);
        }
    });

}));

//change the object used to authenticate to a smaller token, and protects the server from attacks
passport.serializeUser(function(user, done) {
    done(null, user.id);
});
passport.deserializeUser(function(id, done) {
    done(null, { id: id, username: id })
});

//User Sign up requirements and rules
var User = connection.define('user', {
    firstname: {
    type: Sequelize.STRING,
    allowNull: false,
  },
    lastname: {
    type: Sequelize.STRING,
    allowNull: false,
  },
  username: {
    type: Sequelize.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: Sequelize.STRING,
    allowNull: false,
    validate: {
      len: {
        args: [5,10],
        msg: "Your password must be between 5-10 characters"
      },
    }
  },
}, {
  hooks: {
    beforeCreate: function(input){
      input.password = bcrypt.hashSync(input.password, 10);
    }
  }
});

//Teacher signup requirements and rules
var Teacher = connection.define('teacher', {
    firstname: {
    type: Sequelize.STRING,
    allowNull: false,
  },
    lastname: {
    type: Sequelize.STRING,
    allowNull: false,
  },
  username: {
    type: Sequelize.STRING,
    allowNull: false,
    unique: true
  },
  password: {
    type: Sequelize.STRING,
    allowNull: false,
    validate: {
      len: {
        args: [5,10],
        msg: "Your password must be between 5-10 characters"
      },
    }
  },
}, {
  hooks: {
    beforeCreate: function(input){
      input.password = bcrypt.hashSync(input.password, 10);
    }
  }
});



//check login with db
app.post('/check', passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/?msg=Login Credentials do not work'
}));


app.get("/", function(req, res){
  res.render('index', {msg: req.query.msg});
})

app.get('/home', function(req, res){
  res.render('home', {
    user: req.user,
    isAuthenticated: req.isAuthenticated()
  });
})
app.post("/save", function(req, res){
  User.create(req.body).then(function(result){
    res.redirect('/?msg=Account created');
  }).catch(function(err) {
    console.log(err);
    res.redirect('/?msg=' + err.errors[0].message);
  });
})











// database connection via sequelize
connection.sync().then(function() {
  app.listen(port, function() {
      console.log("Listening on:" + port)
  });
});
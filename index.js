
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3030;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 hour

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs')

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(express.json());

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));



function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.render('login');
    }
} 

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.put('/users/:email', async (req, res) => {
    const email = req.params.email;
    const userType = req.body.user_type;
    console.log(`Updating user type for ${email} to ${userType}`);
  
    try {
      const result = await userCollection.updateOne({email: email}, {$set: {user_type: userType}});
      console.log(`User type updated for ${email}: ${result.modifiedCount} document(s) modified`);
      res.send(`User type updated for ${email}: ${result.modifiedCount} document(s) modified`);
    } catch (err) {
      console.error(`Failed to update user type for ${email}: ${err}`);
      res.status(500).send(`Failed to update user type for ${email}: ${err}`);
    }
  });  

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        res.render("index");
        return;
    } else {
        res.render("loggedin", {name: req.session.name});
        return;
    }
});

// Define a route for the sign up page
app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/submit', async (req,res) => {
    try {
        var name = req.body.name;
        var email = req.body.email;
        var password = req.body.password;

        // Validate the user input using Joi
        const schema = Joi.object(
            {
                name: Joi.string().alphanum().max(20).required(),
                email: Joi.string().email().required(),
                password: Joi.string().max(20).required()
            });
        
        const validationResult = schema.validate({name, email, password});
        if (validationResult.error) {
            const { context: { key } } = validationResult.error.details[0];
            const errorMessage = `Please provide a ${key}.<br> <a href="/signup">Try again</a>`;
            res.send(errorMessage);
            return;
        }
    
        // Check if the email is already in use
        const user = await userCollection.findOne({ email: email });
        if (user) {
            res.send(`The email address is already in use. <a href="/signup">Try again</a>`);
        }
    
        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, saltRounds);
    
        // Add the user to the MongoDB database
        const newUser = { name, email, user_type: "user", password: hashedPassword };
        const result = await userCollection.insertOne(newUser);
    
        // Set up a session for the new user
        req.session.authenticated = true;
        req.session.userId = result.insertedId;
        req.session.name = name;
    
        // Redirect the user to the members page
        res.render("members");
    } catch (err) {
        console.error(err);
        res.send('An error occurred. Please try again later.');
    }
});

app.get('/login', (req,res) => {
    res.render('login');
});
  
app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   const errorMessage = `Please provide a ${key}.<br> <a href="/login">Try again</a>`;
        return res.send(errorMessage);
	}

	const result = await userCollection.find({email: email}).project({email: 1, name: 1, user_type:1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.render('login');
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.name = result[0].name;
        req.session.user_type = result[0].user_type
		req.session.cookie.maxAge = expireTime;

		res.render('members');
		return;
	}
	else {
        console.log("incorrect password");
        const errorMessage = `Invalid email/password combination.<br><a href="/login">Try again</a>`;
        res.send(errorMessage);
        return;
    }    
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.render("index");
    }

    res.render("members");

});
  
app.get('/logout', (req,res) => {
	req.session.destroy();
    res.render('index');
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.render("index");
    }
    res.render("loggedin", {name: req.session.name});
});

app.get('/admin', sessionValidation, adminAuthorization,  async (req,res) => {
    // if (!req.session.authenticated) {
    //     res.render("index");
    // }
    const result = await userCollection.find().project({email: 1, name: 1, user_type: 1, _id: 1}).toArray();
    res.render("admin", {users: result});
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
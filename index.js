
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


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

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

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
        var html = `
        <div><button onclick="location.href='/signup';">Sign Up</button></div>
        <div><button onclick="location.href='/login';">Log In</button></div>
        `;
        res.send(html);
        return;
    } else {
        var html = `
            Hello, ${req.session.name}!
            <div><button onclick="location.href='/members';">Go to member's area</button></div>
            <div><button onclick="location.href='/logout';">Logout</button></div>
        `;
        res.send(html);
        return;
    }
});

// Define a route for the sign up page
app.get('/signup', (req, res) => {
    res.send(`
      <form method="post" action="/submit">
        <input name='name' type='text' placeholder='name'><br>
        <input name='email' type='email' placeholder='email'><br>
        <input name='password' type='password' placeholder='password'><br>
        <button>Submit</button>
      </form>
    `);
});
  
app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
            return res.send(errorMessage);
        }
    
        // Check if the email is already in use
        const user = await userCollection.findOne({ email: req.body.email });
        if (user) {
          return res.send(`The email address is already in use. <a href="/signup">Try again</a>`);
        }
    
        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, saltRounds);
    
         // Add the user to the MongoDB database
        await userCollection.insertOne({ name, email, password: hashedPassword });
        console.log("Inserted user");
    
        // // Set up a session for the new user
        // req.session.userId = newUser._id;
    
        // Redirect the user to the members page
        res.redirect('/members');
      } catch (err) {
        console.error(err);
        res.send('An error occurred. Please try again later.');
    }
});
  
app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedIn');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});

app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var html = `
        Hello, ${req.session.name}!
        <div><button onclick="location.href='/members';">Go to member's area</button></div>
        <div><button onclick="location.href='/logout';">Logout</button></div>
    `;
    res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    //generate random 1 to 3 to rand variable
    var rand = Math.floor(Math.random() * 3) + 1;

    if (rand == 1) {
        res.send(`Hello, ${req.session.name}!<br><img src='/fluffy.gif' style='width:250px;'><br>
        <div><button onclick="location.href='/logout';">Sign out</button></div>`);
    }
    else if (rand == 2) {
        res.send(`Hello, ${req.session.name}!<br><img src='/socks.gif' style='width:250px;'><br>
        <div><button onclick="location.href='/logout';">Sign out</button></div>`);
    } else if (rand == 3) {
        res.send(`Hello, ${req.session.name}!<br><img src='/cat.gif' style='width:250px;'><br>
        <div><button onclick="location.href='/logout';">Sign out</button></div>`);
    } else {
        res.send("Invalid request: "+ rand);
    }
});
  
app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
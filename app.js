//jshint esversion:6
import 'dotenv/config';
import  express  from "express";
import bodyParser from "body-parser";
import pg from "pg";
import session from 'express-session';
import passport from 'passport';
import passportLocal from "passport-local"
import bcrypt, { hash } from "bcrypt";
import  GoogleCallbackParameters  from 'passport-google-oauth20';
//import e from 'express';
//import md5 from 'md5';

const app = express();
const port = 3000;
const GoogleStrategy = GoogleCallbackParameters.Strategy;
let currentUserId;
const saltRounds = 10;

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "users",
    password: process.env.DB_PASSWORD,
    port: 5432,
});
  
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate("session"));

// Passport Stratergies

const LocalStrategy = passportLocal.Strategy;

passport.use("local-register",new LocalStrategy(async (username,password,cb)=>{
    try {
        const hashPassword = (await db.query("SELECT password FROM users WHERE email=$1",[username])).rows;
        if(hashPassword.length>0){
            return cb(null,false,{message:"Email already taken."});
        }
        else{
            bcrypt.hash(password,saltRounds,(err,hash)=>{
                if(err){
                    return cb(err);
                }
                else{
                    db.query("INSERT INTO users(email,password) VALUES($1,$2);",[username,hash]);
                    return cb(null,true);
                }
            });
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.use("local-login",new LocalStrategy(async (username,password,cb)=>{
    try {
        const hashPassword = (await db.query("Select password from users WHERE email=$1",[username])).rows;
        if(hashPassword.length ==0){
            return cb(null,false,{message:"User name or password is incorrect"});
        }
        bcrypt.compare(password,hashPassword[0].password,(err,result)=>{
            if(err){
                return cb(err);
            }
            if(result==false){
                return cb(null, false, { message: 'User name or password is incorrect' });
            }
            else{
                currentUserId = Number(hashPassword[0].id);
                return cb(null,result);
            }
        });
    } catch (err) {
        return cb(err);
    }
}))

// passport.serializeUser((user,cb)=>{
//     process.nextTick(()=>{
//         cb(null,{id:user.id,username:user.username})
//     });
// });

// passport.deserializeUser((user,cb)=>{
//     process.nextTick(()=>{
//         cb(null,user);
//     });
// });
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  async function(accessToken, refreshToken, profile, cb) {
    const email = (await db.query("SELECT email FROM users WHERE googleId=$1",[profile.id])).rows;
    //console.log(profile);
        if(email.length>0){
            cb(null,profile);
        }
        else{
            await db.query("INSERT INTO users(googleId) VALUES($1);",[profile.id]);
            cb(null,profile);
        }
  }
));


app.get("/",(req,res)=>{
    res.render("home.ejs");
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
});

app.get("/login",(req,res)=>{
    res.render("login.ejs");
});

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});

app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("secrets.ejs");
    }
    else{
        res.redirect("/login");
    }
});

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit.ejs");
    }
    else{
        res.redirect("/login");
    }
});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;
    console.log(req.user);
});

app.get("/logout",(req,res)=>{
    req.logOut((err)=>{
        if(err){
            return next(err);
        }
    res.redirect("/");
    });
});

app.post("/register",passport.authenticate("local-register",{
    successRedirect : "/secrets",
    failureRedirect : "/register"
}));

app.post("/login",passport.authenticate("local-login",{
    successRedirect : "/secrets",
    failureRedirect : "/login"
}));



















//app.post("/register",async (req,res)=>{
    //const username = req.body.username;
    //const password = req.body.password;
    //bcrypt version
    //const hash = bcrypt.hashSync(password,10);
    //Md5 version
    //const passwordHash = md5(password);
    //try {
    //    await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[username,hash]);
    //    res.render("secrets.ejs");
    //} catch (err) {
    //    console.log(err);
    //}
//});
//app.post("/login",async (req,res)=>{
    // const username = req.body.username;
    // const password = req.body.password;
    
    // try {
    //     const result = (await db.query(`SELECT password FROM users WHERE email = '${username}'`)).rows[0];
    //     const hash = result.password;
    //     //bcrypt version
    //     const es = bcrypt.compareSync(password,hash);
    //     //md5 version
    //     //const md5version = hash ? md5(password) : true;
    //     if(es){
    //         res.render("secrets.ejs");
    //     }
    // } catch (err) {
    //     console.log(err);
    // }
//});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
  
//jshint esversion:6
import 'dotenv/config';
import  express  from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;

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

app.get("/",(req,res)=>{
    res.render("home.ejs");
});

app.get("/login",(req,res)=>{
    res.render("login.ejs");
});

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});

app.post("/register",async (req,res)=>{
    const username = req.body.username;
    const password = req.body.password;
    const hash = bcrypt.hashSync(password,process.env.SECRET);
    
    try {
        await db.query("INSERT INTO users (email,password) VALUES ($1,$2)",[username,hash]);
        res.render("secrets.ejs");
    } catch (err) {
        console.log(err);
    }
});
app.post("/login",async (req,res)=>{
    const username = req.body.username;
    const password = req.body.password;
    
    try {
        const result = (await db.query(`SELECT password FROM users WHERE email = '${username}'`)).rows[0];
        const hash = result.password;
        const es = bcrypt.compareSync(password,hash);
        if(es){
            res.render("secrets.ejs");
        }
    } catch (err) {
        console.log(err);
    }
});




app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
  
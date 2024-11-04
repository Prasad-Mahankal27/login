const express= require('express');
const app=express();

app.set("view engine",'ejs');
app.use(express.json())
app.use(express.urlencoded({extended:true}))

const userRouter=require('./routes/user.routes');
const router = require('./routes/user.routes');

const dotenv=require('dotenv');
dotenv.config(); //this makess access to mongourl in .env file accessible to whole project
const connectToDB=require('./config/db')
connectToDB();
const cookieParser=require('cookie-parser');
app.use(cookieParser())
// app.get('/', (req,res)=>{
//     // res.send("Hello world");
//     res.render('index');
// })
app.use('/user', userRouter) // /user/test

app.listen(3000);
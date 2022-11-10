const express = require("express");

const cors = require("cors")

const app = express();

const mongodb = require("mongodb");

const bcrypt = require("bcryptjs");

const  jwt = require("jsonwebtoken");

const dotenv = require("dotenv").config();

const mongoClient = mongodb.MongoClient;

const URL = process.env.DB;
const DB = "Attendance_Portal";

let users = [];

// midleware
app.use(express.json());
app.use(cors({
    origin: "*",
    credentials:true
}))

let authenticate = (req, res, next) => {
    
    if(req.headers.authorization){
        console.log(req.headers.authorization)
        try {
            let decode = jwt.verify(req.headers.authorization, process.env.SECRET);
            if (decode) {
                next();                                        // next() This is pass the next function Allow to run
            }
        } catch (error) {
            res.status(401).json({ message : "Unauthorized"});
        }
    }else{
        res.status(401).json({message : "Unauthorized"});
    }
}

app.get("/class1-all",authenticate, async function (req, res) {
    try {
        //Step 1 : Create a  Connection between Node.js and MongoDB
        const connection = await mongoClient.connect(URL);

        //Step 2 : Select the DB
        const db = connection.db(DB);

        //Step 3 : Select the Collection
        //Step 4 : Do the Operation (Create, Update, Read, Delete)
        let resUser = await db.collection("class-1st").find().toArray();

        //Step 5 : Close the Connection
        await connection.close()

        res.json(resUser);
    } catch (error) {
        console.log(error)
        //If any error throw error
        res.status(500).json({ message: "Something-went-wrong" })
    }


});

app.post("/class-1st", authenticate, async function (req, res) {
    try {
        //Step 1 : Create a  Connection between Node.js and MongoDB
        const connection = await mongoClient.connect(URL);

        //Step 2 : Select the DB
        const db = connection.db(DB);

        //Step 3 : Select the Collection
        //Step 4 : Do the Operation (Create, Update, Read, Delete)
        await db.collection("class-1st").insertOne(req.body)

        //Step 5 : Close the Connection
        await connection.close()

        res.json({ message: "Data inserted" })
    } catch (error) {
        console.log(error)
        //If any error throw error
        res.status(500).json({ message: "Something-went-wrong" })
    }


});


app.get("/class-1st/:id", authenticate, async function (req, res) {
    try {
        //Step 1 : Create a  Connection between Node.js and MongoDB
        const connection = await mongoClient.connect(URL);

        //Step 2 : Select the DB
        const db = connection.db(DB);

        //Step 3 : Select the Collection
        //Step 4 : Do the Operation (Create, Update, Read, Delete)
        let user = await db.collection("class-1st").findOne({ _id: mongodb.ObjectId(req.params.id) });

        //Step 5 : Close the Connection
        await connection.close()

        res.json(user);
    } catch (error) {
        console.log(error)
        //If any error throw error
        res.status(500).json({ message: "Something-went-wrong" })
    }



})

app.put("/class-1st/:id", authenticate, async function (req, res) {

    try {
        //Step 1 : Create a  Connection between Node.js and MongoDB
        const connection = await mongoClient.connect(URL);

        //Step 2 : Select the DB
        const db = connection.db(DB);

        //Step 3 : Select the Collection
        //Step 4 : Do the Operation (Create, Update, Read, Delete)
        let user = await db.collection("class-1st").findOneAndUpdate({ _id: mongodb.ObjectId(req.params.id) }, { $set: req.body })

        //Step 5 : Close the Connection
        await connection.close()

        res.json(user);
    } catch (error) {
        console.log(error)
        //If any error throw error
        res.status(500).json({ message: "Something-went-wrong" })
    }

})

app.delete("/class-1st/:id", authenticate, async function (req, res) {
    try {
        //Step 1 : Create a  Connection between Node.js and MongoDB
        const connection = await mongoClient.connect(URL);

        //Step 2 : Select the DB
        const db = connection.db(DB);

        //Step 3 : Select the Collection
        //Step 4 : Do the Operation (Create, Update, Read, Delete)
        let user = await db.collection("class-1st").findOneAndDelete({ _id: mongodb.ObjectId(req.params.id) })

        //Step 5 : Close the Connection
        await connection.close()

        res.json(user);
    } catch (error) {
        console.log(error)
        //If any error throw error
        res.status(500).json({ message: "Something-went-wrong" })
    }

})


app.post("/register", async function (req, res) {
    try {
        let connection = await mongoClient.connect(URL);

        let db = connection.db(DB);

        let salt = await bcrypt.genSalt(10);
        console.log(salt)                            //$2a$10$juBT.reHbUr5BwmZAkMLdu This is Salt password

        let hash = await bcrypt.hash(req.body.password, salt);
        console.log(hash);                           //2a$10$juBT.reHbUr5BwmZAkMLdumfxi5H2jC6qblBwjMqdPtLRzNeXadGy
        req.body.password = hash

        await db.collection("private").insertOne(req.body);

        await connection.close();

        res.json({ message: "User Registered Successfully" });
    } catch (error) {
        console.log(error)

        res.json(error)
    }
})

app.post("/login", async function (req, res) {
    try {
        let connection = await mongoClient.connect(URL);
        let db = connection.db(DB);

        let user = await db.collection("private").findOne({ email: req.body.email });
        if (user) {
            let compare = await bcrypt.compare(req.body.password, user.password)
            if (compare) {

                let token = jwt.sign({ _id: user._id }, process.env.SECRET, {expiresIn : "1d"});
                res.json({message:"Successfully Login", token, email:user.email})
            } else {
                res.json({ message: "Username / Password is Wrong" })
            }
        } else {
            res.status(401).json({ message: "Username / Password is wrong" });
        }

    } catch (error) {
        console.log(error);
        res.status(500).json({ message : "Something went wrong"});
    }
})

app.post("/forgot/:id", async function (req, res) {
    try {
        //Step 1 : Create a  Connection between Node.js and MongoDB
        const connection = await mongoClient.connect(URL);

        //Step 2 : Select the DB
        const db = connection.db(DB);

        //Step 3 : Select the Collection
        let salt = await bcrypt.genSalt(10);
        console.log(salt)                            //$2a$10$juBT.reHbUr5BwmZAkMLdu This is Salt password

        let hash = await bcrypt.hash(req.body.password, salt);
        console.log(hash);                           //2a$10$juBT.reHbUr5BwmZAkMLdumfxi5H2jC6qblBwjMqdPtLRzNeXadGy
        req.body.password = hash
        //Step 4 : Do the Operation (Create, Update, Read, Delete)
        let user = await db.collection("private").findOneAndUpdate({ _id: mongodb.ObjectId(req.params.id) }, { $set: req.body })

       
        //Step 5 : Close the Connection
        await connection.close()

        res.json(user);
    } catch (error) {
        console.log(error)
        //If any error throw error
        res.status(500).json({ message: "Something-went-wrong" })
    }
})

app.listen(process.env.PORT || 3000);

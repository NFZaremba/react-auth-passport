import mongoose from "mongoose";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import passport from "passport";
import passportLocal from "passport-local";
import cookieParser from "cookie-parser";
import session from "express-session";
import bcrypt from "bcryptjs";
import User from "./User";
import dotenv from "dotenv";
import { UserInterface } from "./interfaces/UserInterface";

const LocalStrategy = passportLocal.Strategy;

mongoose.connect(
  "mongodb+srv://nfz32:eidcEuQFTvl1uYjl@cluster0.gptnv.mongodb.net/<dbname>?retryWrites=true&w=majority",
  {
    useCreateIndex: true,
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
  (err: Error) => {
    if (err) throw err;
    console.log("Connected to Mongo");
  }
);

// Middleware
const app = express();
app.use(express.json()); // read requests sent
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(
  session({
    secret: "secretcode",
    resave: true,
    saveUninitialized: true,
  })
);
app.use(cookieParser());
app.use(passport.initialize());
app.use(passport.session());

// Passport
passport.use(
  new LocalStrategy((username: string, password: string, done) => {
    User.findOne({ username }, (err, user: any) => {
      if (err) throw err;
      if (!user) return done(null, false);
      bcrypt.compare(password, user.password, (err, result: boolean) => {
        if (err) throw err;
        if (result === true) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      });
    });
  })
);

passport.serializeUser((user: any, cb) => {
  cb(null, user._id);
});

passport.deserializeUser((id: string, cb) => {
  User.findOne({ _id: id }, (err, user: any) => {
    const userInformation = {
      username: user.username,
      isAdmin: user.isAdmin,
      id: user._id,
    };
    cb(err, userInformation);
  });
});

const isAdminMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const { user }: any = req;
  if (user) {
    User.findOne({ username: user.username }, (err, doc: UserInterface) => {
      if (err) throw err;
      if (doc?.isAdmin) {
        next();
      } else {
        res.send("Sorry, only admin's can perform this.");
      }
    });
  } else {
    res.send("Error, you are not logged in.");
  }
};

// Routes
app.post("/register", async (req: Request, res: Response) => {
  const { username, password } = req?.body;
  if (
    !username ||
    !password ||
    typeof username !== "string" ||
    typeof password !== "string"
  ) {
    res.send("Improper Values");
    return;
  }

  User.findOne({ username }, async (err: Error, doc: UserInterface) => {
    if (err) throw err;
    if (doc) res.send("User Already Exists");
    if (!doc) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const newUser = new User({
        username: req.body.username,
        password: hashedPassword,
        isAdmin: true,
      });
      await newUser.save();
      res.send("success");
    }
  });
});

app.post(
  "/login",
  passport.authenticate("local"),
  (req: Request, res: Response) => {
    res.send("success");
  }
);

app.get("/user", (req: Request, res: Response) => {
  res.send(req.user);
});

app.get("/logout", (req, res) => {
  req.logout();

  res.send("success");
});

app.post("/deleteuser", isAdminMiddleware, async (req, res) => {
  const { id } = req.body;
  await User.findByIdAndDelete(id, (err: Error) => {
    if (err) throw err;
  });
  res.send("success");
});

app.get("/getallusers", isAdminMiddleware, async (req, res) => {
  await User.find({}, (err: Error, data: UserInterface[]) => {
    if (err) throw Error;
    res.send(data);
  });
});

app.listen(4000, () => {
  console.log("Server Started");
});

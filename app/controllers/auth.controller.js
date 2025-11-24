// app/controllers/auth.controller.js
import config from "../config/auth.config.js";
import db from "../models/index.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
 
const User = db.User;
const Role = db.Role;
 
export const signup = async (req, res) => {
    try {
        // Create a new user
        const user = new User({
            username: req.body.username,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password, 8),
        });
 
        const role = await Role.findOne({ name: "user" });
        user.roles = [role._id];
 
        // Save user to the database
        await user.save();
        res.status(201).json({ message: "User was registered successfully!" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};
 
export const signin = async (req, res) => {
    try {
        // Find user by username
        const user = await User.findOne({ username: req.body.username }).populate(
            "roles",
            "-__v",
        );
 
        if (!user) {
            return res.status(404).json({ message: "User Not found." });
        }
 
        // Validate password
        const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
        if (!passwordIsValid) {
            return res.status(401).json({
                accessToken: null,
                message: "Invalid Password!",
            });
        }
        console.log(config.secret);
 
        // Generate JWT
        const token = jwt.sign({ id: user.id }, config.secret, {
            algorithm: "HS256",
            expiresIn: 3600, // 1 hour
        });

        const refreshToken = jwt.sign({ id: user.id }, config.secret, {
            algorithm: "HS256",
            expiresIn: '1d', // 24 hours
        });
        res.cookie('refreshToken', refreshToken, { httpOnly: true, sameSite: 'strict' });

        
 
        // Extract user roles
        const authorities = user.roles.map((role) => `ROLE_${role.name.toUpperCase()}`);
 
        res.status(200).json({
            id: user._id,
            username: user.username,
            email: user.email,
            roles: authorities,
            accessToken: token,
        });
    } catch (err) {
        
        res.status(500).json({ message: err.message });
    }
};

export const refreshToken = async (req, res) => {
const refreshToken = req.cookies['refreshToken'];
  if (!refreshToken) {
    return res.status(401).send('Access Denied. No refresh token provided.');
  }

  try {
    const decoded = jwt.verify(refreshToken, config.secret);
    const accessToken = jwt.sign({ id: decoded.id }, config.secret, { algorithm: "HS256",expiresIn: '1h' });

    res
      .header('Authorization', accessToken)
      .send(decoded.id);
  } catch (error) {
    return res.status(400).send('Invalid refresh token.');
  }
};
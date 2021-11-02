const { checkToken } = require("../../validation/checkToken");

const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const keys = require("../../config/keys");
const passport = require("passport");

// Load input validation
const validateRegisterInput = require("../../validation/register");
const validateLoginInput = require("../../validation/login");
const validateAddInput = require("../../validation/userValidation");

// Load User model
const User = require("../../models/User");

// @route POST api/users/register
// @desc Register user
// @access Public
router.post("/register", (req, res) => {
    // Form validation

    const { errors, isValid } = validateRegisterInput(req.body);

    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    User.findOne({ email: req.body.email }).then((user) => {
        if (user) {
            return res.status(400).json({ email: "Email already exists" });
        } else {
            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                password: req.body.password,
            });

            // Hash password before saving in database
            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if (err) throw err;
                    newUser.password = hash;
                    newUser
                        .save()
                        .then((user) => res.json(user))
                        .catch((err) => console.log(err));
                });
            });
        }
    });
});

// @route POST api/users/login
// @desc Login user and return JWT token
// @access Public
router.post("/login", (req, res) => {
    // Form validation

    const { errors, isValid } = validateLoginInput(req.body);

    // Check validation
    if (!isValid) {
        return res.status(400).json(errors);
    }

    const email = req.body.email;
    const password = req.body.password;

    // Find user by email
    User.findOne({ email }).then((user) => {
        // Check if user exists
        if (!user) {
            return res.status(404).json({ emailNotFound: "Email not found" });
        }

        // Check password
        bcrypt.compare(password, user.password).then((isMatch) => {
            if (isMatch) {
                // User matched
                // Create JWT Payload
                const payload = {
                    id: user.id,
                    name: user.name,
                };

                // Sign token
                jwt.sign(
                    payload,
                    keys.secretOrKey,
                    {
                        expiresIn: 31556926, // 1 year in seconds
                    },
                    (err, token) => {
                        res.json({
                            success: true,
                            token: token,
                        });
                    }
                );
            } else {
                return res
                    .status(400)
                    .json({ passwordIncorrect: "Password incorrect" });
            }
        });
    });
});

const updateUser = (req, res, next) => {
    if (req.user) {
        return next();
    }

    res.status(401).json({ msg: "Unauthorized!" });
};

router.post("/updateUser", checkToken, updateUser, (req, res) => {
    const { errors, isValid } = validateAddInput(req.body);

    if (!isValid) {
        return res.status(400).json(errors);
    }

    const { _id, email, name } = req.body;

    const filter = _id;
    const update = { email, name };

    User.findByIdAndUpdate(
        filter,
        update,
        { new: true, useFindAndModify: false },
        (err, doc) => {
            // res.status(200).json({ msg: "Successfully added!" });
            if (err) {
                res.json({ msg: err });
            } else {
                res.status(200).json({
                    msg: "Successfully updated!",
                    user: doc,
                });
            }
        }
    );
});

const getListUser = (req, res, next) => {
    if (req.user) {
        return next();
    }

    res.status(401).json({ msg: "Unauthorized!" });
};

router.post("/getListUser", checkToken, getListUser, (req, res) => {
    User.find(req.body).then((user) => {
        if (user.length !== 0) {
            return res.status(200).json(user);
        } else {
            return res.status(200).json({ msg: "No user found!" });
        }
    });
});

const insertUser = (req, res, next) => {
    if (req.user) {
        return next();
    }

    res.status(401).json({ msg: "Unauthorized!" });
};

router.post("/insertUser", checkToken, insertUser, (req, res) => {
    const { errors, isValid } = validateAddInput(req.body);

    if (!isValid) {
        return res.status(400).json(errors);
    }

    const { email, name } = req.body;

    User.findOne({ email }).then((user) => {
        if (user) {
            return res.status(200).json({ email: "Email already exists!" });
        } else {
            const newUser = new User({
                name,
                email,
                password: "123456",
            });

            bcrypt.genSalt(10, (err, salt) => {
                bcrypt.hash(newUser.password, salt, (err, hash) => {
                    if (err) throw err;
                    newUser.password = hash;
                    newUser
                        .save()
                        .then(() => res.json({ msg: "Successfully added!" }))
                        .catch((err) => console.log(err));
                });
            });
        }
    });
});

const deleteUser = (req, res, next) => {
    if (req.user) {
        return next();
    }

    res.status(401).json({ msg: "Unauthorized!" });
};

router.post("/deleteUser", checkToken, deleteUser, (req, res) => {
    const filter = req.body._id;

    User.findByIdAndDelete(filter, (err, doc) => {
        if (err) {
            res.json({ msg: err });
        } else {
            res.status(200).json({ msg: "Successfully deleted!" });
        }
    });
});

module.exports = router;

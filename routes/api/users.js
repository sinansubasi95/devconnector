const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt  = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post(
    '/', 
    [
        check('name', 'Name is required')
            .not()
            .isEmpty(),
        check('email', 'Please include a valid email')
            .isEmail(),
        check('password', 'Please enter a password with 6 or more characters')
            .isLength({ min: 6 })
    ], 
    async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        // Destruct req.body
        const { name, email, password } = req.body;

        try {
            // See if user exists
            let user = await User.findOne({ email: email })

            if(user) {
                // 400 is bad request and 200 is OK.
                return res
                    .status(400)
                    .json({ errors: [{ msg: 'User already exists' }] });
            }

            // Get user gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            });          

            user = new User({
                name,
                email,
                avatar,
                password
            });

            // Encrypt password with bcrpyt
            const salt = await bcrypt.genSalt(10);

            user.password = await bcrypt.hash(password, salt);

            await user.save();
            
            // Return jsonwebtoken. The reason I am returning jsonwebtoken is because in the front-end when a user registers i want them to get logged in right away and in order to be logged in you have to have that token 
            const payload = {
                user: {
                    id: user.id // _id(mongodb) = user.id(here)
                }
            }

            jwt.sign(
                payload, 
                config.get('jwtSecret'),
                { expiresIn: 360000 }, 
                (err, token) => {
                    if(err) throw err;
                    res.json({ token });
                }
            );

        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server error');
        }

    }
);

module.exports = router;
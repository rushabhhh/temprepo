const express = require('express');
const router = express.Router();
const db = require("../modules/database/database");
const { logger } = require('../services/logger/logger');
const BcryptUtil = require('../utils/bcrypt');
const JWTUtil = require('../utils/jwt');
const GoogleUtil = require('../utils/google');

// Just for Testing purpose in development time
router.get("/api/test", async (req, res) => {
    try {
        const result = await db.query('SELECT NOW()'); // checking Database
        res.status(200).json({ currentTime: result });
    } catch (error) {
        logger.error(`Error getting current time: ${error.message}`);
        res.status(500).json({ error: "Failed to get current time from DB" });
    }
})

// Health check endpoint
router.get("/", ( _ , res) => {
    res.status(200).json(
        {
          isResponding: true,
          message: "Cryptify server up and running",
        });
});

// Register a new user
router.post("/api/register", async (req, res, next) => {
    const { email, phone, fname, lname, dob, password, trx_pin, dateOfBirth } = req.body;

    // Validate required fields
    if (!email || !phone || !fname || !lname || !password || !trx_pin) {
        return res.status(400).json({
            status: 400,
            message: 'All fields (email, phone, fname, lname, password, trx_pin) are required'
        });
    }

    try {
        // Validate date format
        const parsedDate = new Date(dateOfBirth);
        if (isNaN(parsedDate.getTime())) {
            return res.status(400).json({
                status: 400,
                message: 'Invalid date format. Use YYYY-MM-DD'
            });
        }

        // Validate age (optional)
        const today = new Date();
        const minDate = new Date('1900-01-01');
        if (parsedDate > today || parsedDate < minDate) {
            return res.status(400).json({
                status: 400,
                message: 'Invalid date of birth'
            });
        }

        // Format date for PostgreSQL
        const formattedDate = parsedDate.toISOString().split('T')[0];

        return db.tx(async (t) => {
            try {
                // Check for existing user
                const existingUser = await t.oneOrNone(
                    `SELECT email, phone_number 
                     FROM users 
                     WHERE email = $1 OR phone_number = $2`,
                    [email, phone]
                );

                if (existingUser) {
                    const field = existingUser.email === email ? 'email' : 'phone number';
                    return res.status(409).json({
                        status: 409,
                        message: `User with this ${field} already exists`
                    });
                }

                // Hash password and transaction PIN
                let passwordHash, pinHash;
                try {
                    passwordHash = await BcryptUtil.hash(password);
                    pinHash = await BcryptUtil.hash(trx_pin);
                } catch (hashError) {
                    logger.error('Error hashing credentials:', hashError);
                    return res.status(500).json({
                        status: 500,
                        message: 'Error processing credentials'
                    });
                }

                let newUser;
                try {
                    newUser = await t.one(
                        `INSERT INTO users (
                            first_name,
                            last_name,
                            email,
                            phone_number,
                            password_hash,
                            date_of_birth,  
                            transaction_pin
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                        RETURNING id, email`,
                        [fname, lname, email, phone, passwordHash, formattedDate, pinHash]
                    );
                } catch (dbError) {
                    logger.error('Database error during user creation:', dbError);
                    return res.status(500).json({
                        status: 500,
                        message: 'Error creating user account'
                    });
                }

                // Generate JWT token
                let token;
                try {
                    token = JWTUtil.generateToken({
                        userId: newUser.id,
                        email: newUser.email
                    });
                } catch (tokenError) {
                    logger.error('Error generating token:', tokenError);
                    return res.status(500).json({
                        status: 500,
                        message: 'Error generating access token'
                    });
                }

                logger.info(`New User created successfully: ${newUser.id}`);

                return res.status(201).json({
                    success: true,
                    userId: newUser.id,
                    token: token
                });
            } catch (error) {
                logger.error('Unexpected error in registration process:', error);
                return res.status(500).json({
                    status: 500,
                    message: 'An unexpected error occurred'
                });
            }
        });
    } catch (error) {
        logger.error('Transaction error:', error);
        return res.status(500).json({
            status: 500,
            message: 'Database transaction failed'
        });
    }
});

// Update the login endpoint
router.post("/api/login", async (req, res) => {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
        return res.status(400).json({
            status: 400,
            message: 'Email and password are required'
        });
    }

    try {   
        // Find user with additional details
        const user = await db.oneOrNone(
            `SELECT id, email, password_hash, first_name, last_name, phone_number 
             FROM users 
             WHERE email = $1`,
            [email]
        );

        if (!user) {
            return res.status(401).json({
                status: 401,
                message: 'Invalid email or password'
            });
        }

        // Verify password
        try {
            const isValidPassword = await BcryptUtil.compare(password, user.password_hash);
            if (!isValidPassword) {
                return res.status(401).json({
                    status: 401,
                    message: 'Invalid email or password'
                });
            }
        } catch (hashError) {
            logger.error('Error verifying password:', hashError);
            return res.status(500).json({
                status: 500,
                message: 'Error processing credentials'
            });
        } 

        // Generate JWT token
        let token;
        try {
            token = JWTUtil.generateToken({
                userId: user.id,
                email: user.email
            });
        } catch (tokenError) {
            logger.error('Error generating token:', tokenError);
            return res.status(500).json({
                status: 500,
                message: 'Error generating access token'
            });
        }

        logger.info(`User logged in successfully: ${user.id}`);

        return res.status(200).json({
            success: true,
            userId: user.id,
            token: token,
            userData: {
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                phoneNumber: user.phone_number
            }
        });

    } catch (error) {
        logger.error('Login error:', error);
        return res.status(500).json({
            status: 500,
            message: 'An unexpected error occurred'
        });
    }
});

// Also update the Google login endpoint similarly
router.post("/api/google-login", async (req, res) => {
    const { idToken } = req.body;
    logger.info(`Google login request received`);

    if (!idToken) {
        return res.status(400).json({
            status: 400,
            message: 'Google ID token is required'
        });
    }

    try {
        // Verify Google token
        const googleUser = await GoogleUtil.verifyToken(idToken);

        if (!googleUser.email_verified) {
            return res.status(401).json({
                status: 401,
                message: 'Email not verified with Google'
            });
        }

        // Check if user exists
        const user = await db.oneOrNone(
            `SELECT id, email, first_name, last_name, phone_number 
             FROM users WHERE email = $1`,
            [googleUser.email]
        );

        if (!user) {
            return res.status(404).json({
                status: 404,
                message: 'Please sign up first',
                isNewUser: true
            });
        }

        // Generate JWT token
        const token = JWTUtil.generateToken({
            userId: user.id,
            email: user.email,
            google_id: googleUser.google_id
        });

        logger.info(`Google login successful for user: ${googleUser.email}`);

        return res.status(200).json({
            success: true,
            userId: user.id,
            token: token,
            userData: {
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                phoneNumber: user.phone_number
            }
        });

    } catch (error) {
        logger.error('Google login error:', error);
        return res.status(500).json({
            status: 500,
            message: 'Authentication failed'
        });
    }
});

router.post('/api/check-user', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({
      status: 400,
      message: 'Email is required',
    });
  }

  try {
    const user = await db.oneOrNone(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (user) {
        logger.info(`User exists: ${email}`);
      return res.status(200).json({ exists: true });
    } else {
      return res.status(200).json({ exists: false });
    }
  } catch (error) {
    logger.error('Error checking user existence:', error);
    return res.status(500).json({
      status: 500,
      message: 'An unexpected error occurred',
    });
  }
});

router.get('/api/get-balance/:userId', async (req, res) => {
    const { userId } = req.params;

    if (!userId) {
        return res.status(400).json({ status: 400, message: 'User ID is required' });
    }

    try {
        const balances = await db.any(
            `SELECT crypto, balance FROM user_balances WHERE user_id = $1`,
            [userId]
        );

        if (!balances.length) {
            return res.status(404).json({ status: 404, message: 'No balances found for this user' });
        }

        // Convert list to key-value format
        const balanceMap = {};
        balances.forEach(({ crypto, balance }) => {
            balanceMap[crypto] = balance;
        });

        return res.status(200).json({ success: true, balances: balanceMap });
    } catch (error) {
        logger.error('Error fetching user balance:', error);
        return res.status(500).json({ status: 500, message: 'Failed to fetch balance' });
    }
});

module.exports = router;
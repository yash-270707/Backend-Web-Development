
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const router = express.Router();

// In paths and function names ko apne project se match karna.
const userRepository = require('../repositories/userRepository');
const sessionStore = require('../sessions/sessionStore');
const requireSession = require('../middleware/requireSession');

const SESSION_MAX_AGE = 60 * 60 * 1000;

function cookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === 'true',
    sameSite: 'lax',
    signed: true,
    path: '/',
    maxAge: SESSION_MAX_AGE
  };
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email
  };
}

// LOGIN
router.post('/login', async (req, res, next) => {
  try {
    const email =
      typeof req.body?.email === 'string'
        ? req.body.email.trim().toLowerCase()
        : '';

    const password =
      typeof req.body?.password === 'string'
        ? req.body.password
        : '';

    if (!email || !password) {
      return res.status(400).json({
        error: { code: 'INVALID_INPUT', message: 'Invalid input' }
      });
    }

    const user = await userRepository.findByEmail(email);

    // Apne schema ke actual password-hash field ka naam check karna.
    const validPassword =
      user &&
      await bcrypt.compare(password, user.passwordHash);

    if (!validPassword) {
      return res.status(401).json({
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      });
    }

    const sid = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + SESSION_MAX_AGE);

    // Session store ko sid -> { userId, expiresAt } store karna hoga.
    sessionStore.create(sid, {
      userId: user.id,
      expiresAt
    });

    res.cookie('sid', sid, cookieOptions());

    return res.status(200).json({
      data: publicUser(user)
    });
  } catch (error) {
    next(error);
  }
});

// CURRENT USER
router.get('/me', requireSession, (req, res) => {
  return res.status(200).json({
    data: publicUser(req.user)
  });
});

// LOGOUT
router.post('/logout', (req, res, next) => {
  try {
    const sid = req.signedCookies?.sid;

    if (typeof sid === 'string') {
      sessionStore.destroy(sid);
    }

    // Cookie clear karte waqt matching scope/options rakho.
    const options = cookieOptions();
    delete options.maxAge;

    res.clearCookie('sid', options);

    return res.status(204).send();
  } catch (error) {
    next(error);
  }
});

module.exports = router;
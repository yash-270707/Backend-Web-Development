
const sessionStore = require("../sessions/sessionStore");
const userRepository = require("../repositories/userRepository");

module.exports = async function requireSession(req, res, next) {
  try {
    const sid = req.signedCookies?.sid;

    if (!sid || typeof sid !== "string") {
      return res.status(401).json({
        error: "AUTH_REQUIRED"
      });
    }

    const session = sessionStore.get(sid);

    if (
      !session ||
      !session.userId ||
      !session.expiresAt ||
      new Date(session.expiresAt) <= new Date()
    ) {
      if (session) {
        sessionStore.destroy(sid);
      }

      return res.status(401).json({
        error: "AUTH_REQUIRED"
      });
    }

    const user = await userRepository.findPublicById(session.userId);

    if (!user) {
      sessionStore.destroy(sid);

      return res.status(401).json({
        error: "AUTH_REQUIRED"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
};

const sessions = new Map();

// Create a new server-side session
function create(sid, { userId, expiresAt }) {
  sessions.set(sid, {
    userId,
    expiresAt: new Date(expiresAt)
  });
}

// Get a session and remove it if expired
function get(sid) {
  const session = sessions.get(sid);

  if (!session) {
    return null;
  }

  if (new Date(session.expiresAt).getTime() <= Date.now()) {
    sessions.delete(sid);
    return null;
  }

  return session;
}

// Destroy a session during logout
function destroy(sid) {
  sessions.delete(sid);
}

module.exports = {
  create,
  get,
  destroy
};
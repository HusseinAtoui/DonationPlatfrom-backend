// middleware/authorize.js
function authorizeRoles(...allowed) {
  const allowedNorm = allowed.map(r => String(r).toLowerCase());
  return (req, res, next) => {
    const raw = req.user?.role ?? req.user?.scope ?? req.user?.roles?.[0];
    const role = String(raw || '').toLowerCase();

    // Only "user" and "ngo" are considered valid now
    if (!['user', 'ngo', 'admin'].includes(role)) {
      return res.status(403).json({ error: `Not authorized: unsupported role "${raw}"` });
    }
    if (!allowedNorm.includes(role) && !allowedNorm.includes('admin')) {
      return res.status(403).json({ error: `Not authorized: role "${role}" is not allowed` });
    }
    // normalize on req for downstream checks
    req.user.role = role;
    next();
  };
}

module.exports = { authorizeRoles };

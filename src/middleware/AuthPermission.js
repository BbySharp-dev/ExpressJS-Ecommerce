const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { CONFIG_MESSAGE_ERRORS, CONFIG_PERMISSIONS } = require("../configs");
const { isTokenInBlacklist } = require("../utils");
dotenv.config();

const handleUnauthorizedError = (res) => {
  return res.status(CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status).json({
    status: "Error",
    message: "Unauthorized",
    typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
    data: null,
  });
};

const AuthPermission = (permission, isAuthMe, isPublic) => (req, res, next) => {
  try {
    if (req.headers?.authorization) {
      const token = req.headers.authorization.split(" ")[1];
      if (!isTokenInBlacklist(token)) {
        jwt.verify(
          token,
          process.env.ACCESS_TOKEN_SECRET,
          function (err, user) {
          
            if (err) {
              return handleUnauthorizedError(res);
            }
            if (
              user?.permissions?.includes(permission) ||
              user?.permissions?.includes(CONFIG_PERMISSIONS.ADMIN) ||
              isAuthMe
            ) {
              req.userId = user.id;
              req.isPermission = true;
              req.permissions = user?.permissions
              next();
              return;
            } else {
              return handleUnauthorizedError(res);
            }
          }
        );
      } else {
        return handleUnauthorizedError(res);
      }
    } else if (isPublic) {
      next();
    } else {
      return handleUnauthorizedError(res);
    }
  } catch (e) {
    return handleUnauthorizedError(res);
  }
};

module.exports = {
  AuthPermission,
};

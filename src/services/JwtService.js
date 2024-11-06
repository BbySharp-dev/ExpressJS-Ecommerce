const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const { CONFIG_MESSAGE_ERRORS } = require("../configs");
dotenv.config();

const generateToken = async (payload, secretKey, expire) => {
  const token = jwt.sign(
    {
      ...payload,
    },
    secretKey,
    { expiresIn: expire }
  );

  return token;
};

const refreshTokenJwtService = (token) => {
  return new Promise((resolve, reject) => {
    try {
      jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
        if (err) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
            message: "Unauthorized",
            statusMessage: "Error",
            data: null,
            typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          });
        }
        const access_token = await generateToken(
          {
            id: user?.id,
            permissions: user?.permissions,
          },
          process.env.ACCESS_TOKEN_SECRET,
          process.env.ACCESS_TOKEN_EXPIRE
        );
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Success",
          statusMessage: "Success",
          data: {
            access_token: access_token
          },
          typeError: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.type,
        });
      });
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  generateToken,
  refreshTokenJwtService,
};

const AuthService = require("../services/AuthService");
const JwtService = require("../services/JwtService");
const UserService = require("../services/UserService");
const { validateRequiredInput } = require("../utils");
const { CONFIG_MESSAGE_ERRORS } = require("../configs");

const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const REGEX_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const REGEX_PASSWORD =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
    const isCheckEmail = REGEX_EMAIL.test(email);
    const isCheckPassword = REGEX_PASSWORD.test(password);

    const requiredFields = validateRequiredInput(req.body, [
      "email",
      "password",
    ]);

    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
      });
    } else if (!isCheckEmail) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "INVALID",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: "The field must a email",
      });
    } else if (!isCheckPassword) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message:
          'The password must be at least 6 characters long and include uppercase letters, lowercase letters, numbers, and special characters."',
      });
    }
    const response = await AuthService.registerUser(req.body);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const loginUser = async (req, res) => {
  try {
    const { email, password} = req.body;
    const REGEX_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const REGEX_PASSWORD =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
    const isCheckEmail = REGEX_EMAIL.test(email);
    const isCheckPassword = REGEX_PASSWORD.test(password);
    const requiredFields = validateRequiredInput(req.body, [
      "email",
      "password",
    ]);

    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
      });
    } else if (!isCheckEmail) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "INVALID",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: "The field must a email",
      });
    } else if (!isCheckPassword) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message:
          'The password must be at least 6 characters long and include uppercase letters, lowercase letters, numbers, and special characters."',
      });
    }
    const response = await AuthService.loginUser(req.body);
    const {
      data,
      status,
      typeError,
      message,
      statusMessage,
      access_token,
      refresh_token,
    } = response;
    res.cookie("refresh_token", refresh_token, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      path: "/",
    });
    return res.status(status).json({
      typeError,
      data: {
        user: data,
        access_token,
        refresh_token,
      },
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const refreshToken = async (req, res) => {
  try {
    const token = req.headers["authorization"].split(" ")[1];
    if (!token) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        message: "Unauthorized",
        typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
        data: null,
      });
    }
    const response = await JwtService.refreshTokenJwtService(token);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const logoutUser = async (req, res) => {
  try {
    const accessToken = req.headers?.authorization?.split(" ")[1];
    const response = await AuthService.logoutUser(res, accessToken);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const getAuthMe = async (req, res) => {
  try {
    const userId = req.userId;
    const response = await UserService.getDetailsUser(userId);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const updateAuthMe = async (req, res) => {
  try {
    const userId = req.userId;
    const isPermission = req.isPermission;
    const response = await AuthService.updateAuthMe(
      userId,
      req.body,
      isPermission
    );
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const updateDeviceToken = async (req, res) => {
  try {
    const userId = req.userId;
    const isPermission = req.isPermission;
    const response = await AuthService.updateDeviceToken(
      userId,
      req.body,
      isPermission
    );
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const changePasswordMe = async (req, res) => {
  try {
    const userId = req.userId;
    const newPassword = req.body.newPassword;
    const currentPassword = req.body.currentPassword;
    const requiredFields = validateRequiredInput(
      { currentPassword, newPassword },
      ["currentPassword", "newPassword"]
    );
    const accessToken = req?.headers?.authorization?.split(" ")[1];
    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
      });
    }
    const response = await AuthService.changePasswordMe(
      userId,
      { newPassword, currentPassword },
      res,
      accessToken
    );
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const forgotPasswordMe = async (req, res) => {
  try {
    const email = req.body.email;

    if (!email) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field email is required`,
        data: null,
      });
    }
    const response = await AuthService.forgotPasswordMe(email);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const resetPasswordMe = async (req, res) => {
  try {
    const { secretKey, newPassword } = req.body;
    const requiredFields = validateRequiredInput({ secretKey, newPassword }, [
      "secretKey",
      "newPassword",
    ]);
    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
      });
    }

    const response = await AuthService.resetPasswordMe(secretKey, newPassword);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const registerGoogle = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The idToken is required`,
      });
    }

    const response = await AuthService.registerGoogle(idToken);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const loginGoogle = async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The idToken is required`,
      });
    }

    const response = await AuthService.loginGoogle(req.body);
    const {
      data,
      status,
      typeError,
      message,
      statusMessage,
      access_token,
      refresh_token,
    } = response;

    // res.cookie("refresh_token", refresh_token, {
    //   httpOnly: true,
    //   secure: false,
    //   sameSite: "strict",
    //   path: "/",
    // });
    return res.status(status).json({
      typeError,
      data: {
        user: data,
        access_token,
        refresh_token,
      },
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const registerFacebook = async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field idToken is required`,
      });
    }

    const response = await AuthService.registerFacebook(idToken);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

const loginFacebook = async (req, res) => {
  try {
    const { idToken } = req.body;

    if (!idToken) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field idToken is required`,
      });
    }

    const response = await AuthService.loginFacebook(req.body);
    const { data, status, typeError, message, statusMessage,refresh_token,access_token } = response;
    return res.status(status).json({
      typeError,
      data: {
        user: data,
        access_token,
        refresh_token,
      },
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      typeError: "Internal Server Error",
      data: null,
      status: "Error",
    });
  }
};

module.exports = {
  registerUser,
  loginUser,
  refreshToken,
  logoutUser,
  getAuthMe,
  updateAuthMe,
  changePasswordMe,
  forgotPasswordMe,
  resetPasswordMe,
  registerGoogle,
  registerFacebook,
  loginGoogle,
  loginFacebook,
  updateDeviceToken
};

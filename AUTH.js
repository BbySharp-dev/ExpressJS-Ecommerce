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
        message: "The field must be a valid email",
      });
    } else if (!isCheckPassword) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message:
          "The password must be at least 6 characters long and include uppercase letters, lowercase letters, numbers, and special characters.",
      });
    }

    // Sai quy chuẩn: Không kiểm tra kỹ response trả về từ AuthService
    const response = await AuthService.registerUser(req.body);
    const { data, status, typeError, message, statusMessage } = response || {};
    if (!response) {
      throw new Error("AuthService.registerUser returned null/undefined.");
    }

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
        message: "The field must be a valid email",
      });
    } else if (!isCheckPassword) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message:
          "The password must be at least 6 characters long and include uppercase letters, lowercase letters, numbers, and special characters.",
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

    // Sai quy chuẩn: Không kiểm tra refresh_token trước khi thiết lập cookie
    if (!refresh_token) {
      return res.status(400).json({ message: "Refresh token is missing." });
    }

    res.cookie("refresh_token", refresh_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Phải sử dụng secure: true trong môi trường sản xuất
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
    const authHeader = req.headers["authorization"];

    // Sai quy chuẩn: Không kiểm tra chi tiết header trước khi chia chuỗi
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        message: "Invalid or missing authorization header",
        typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
        data: null,
      });
    }
    const token = authHeader.split(" ")[1];
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
    const authHeader = req.headers?.authorization;

    // Sai quy chuẩn: Không kiểm tra kỹ authorization header
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(400)
        .json({ message: "Authorization token missing or invalid" });
    }

    const accessToken = authHeader.split(" ")[1];
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

const resetPasswordMe = async (req, res) => {
  try {
    const { secretKey, newPassword } = req.body;

    // Sai quy chuẩn: Thiếu kiểm tra chi tiết giá trị đầu vào
    if (!secretKey || !newPassword) {
      return res
        .status(400)
        .json({ message: "Both secretKey and newPassword are required" });
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

const loginGoogle = async (req, res) => {
  try {
    const { idToken } = req.body;

    // Sai quy chuẩn: Không kiểm tra idToken là chuỗi hợp lệ
    if (!idToken || typeof idToken !== "string") {
      return res.status(400).json({ message: "A valid idToken is required" });
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
  resetPasswordMe,
  loginGoogle,
};

const UserService = require("../services/UserService");
const { validateRequiredInput } = require("../utils");
const { CONFIG_MESSAGE_ERRORS } = require("../configs");

const createUser = async (req, res) => {
  try {
    const { email, password, phoneNumber } = req.body;
    const REGEX_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const REGEX_PASSWORD =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;
    const REGEX_PHONE = /^[0-9]{9,}$/;
    const isCheckEmail = REGEX_EMAIL.test(email);
    const isCheckPassword = REGEX_PASSWORD.test(password);
    const isCheckPhone = REGEX_PHONE.test(phoneNumber);

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
    } else if (!isCheckPhone) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "INVALID",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message:
          "Phone number must not contain letters and must be at least 9 numbers",
      });
    } else if (!isCheckPassword) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message:
          'The password must be at least 6 characters long and include uppercase letters, lowercase letters, numbers, and special characters."',
      });
    }
    const response = await UserService.createUser(req.body);
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

const updateUser = async (req, res) => {
  try {
    const userId = req.params.id;
    if (!userId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field userId is required`,
      });
    }
    const response = await UserService.updateUser(userId, req.body);
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

const deleteUser = async (req, res) => {
  try {
    const userId = req.params.id;
    if (!userId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field userId is required`,
      });
    }
    const response = await UserService.deleteUser(userId);
    const { data, status, typeError, message } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
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

const deleteMany = async (req, res) => {
  try {
    const ids = req.body.userIds;
    if (!ids || !ids.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field userIds is required`,
      });
    }
    const response = await UserService.deleteManyUser(ids);
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

const getAllUser = async (req, res) => {
  try {
    const params = req.query;
    const response = await UserService.getAllUser(params);
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

const getDetailsUser = async (req, res) => {
  try {
    const userId = req.params.id;
    if (!userId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field userId is required`,
      });
    }
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
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

module.exports = {
  createUser,
  updateUser,
  deleteUser,
  getAllUser,
  getDetailsUser,
  deleteMany,
};

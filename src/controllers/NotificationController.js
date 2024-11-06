const NotificationService = require("../services/NotificationService");
const { CONFIG_MESSAGE_ERRORS } = require("../configs");

const getListNotifications = async (req, res) => {
  try {
    const userId = req.userId;
    const params = req.query;

    const response = await NotificationService.getListNotifications(
      userId,
      params,
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


const readOneNotification = async (req, res) => {
  try {
    const userId = req.userId;
    const permissions = req.permissions
    const notificationId = req.params.id;
    if (!notificationId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field notificationId is required`,
      });
    }

    const response = await NotificationService.readOneNotification(
      userId,
      notificationId,
      permissions
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

const deleteNotification = async (req, res) => {
  try {
    const userId = req.userId;
    const notificationId = req.params.id;
    const permissions = req.permissions

    if (!notificationId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field notificationId is required`,
      });
    }

    const response = await NotificationService.deleteNotification(
      userId,
      notificationId,
      permissions
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

const readAllNotification = async (req, res) => {
  try {
    const userId = req.userId;

    const response = await NotificationService.readAllNotification(
      userId,
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

module.exports = {
  getListNotifications,
  readOneNotification,
  deleteNotification,
  readAllNotification,
};

const { CONFIG_MESSAGE_ERRORS, PAYMENT_TYPES } = require("../configs");
const { validateRequiredInput } = require("../utils");
const PaymentTypeService = require("../services/PaymentTypeService");

const createPaymentType = async (req, res) => {
  try {
    const requiredFields = validateRequiredInput(req.body, ["name"]);
    const { type } = req.body;
    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
        data: null,
      });
    }
    if (!Object.values(PAYMENT_TYPES).includes(type)) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `Invalid payment type. Allowed types are: ${Object.values(
          PAYMENT_TYPES
        ).join(", ")}`,
        data: null,
      });
    }
    const response = await PaymentTypeService.createPaymentType(req.body);
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

const updatePaymentType = async (req, res) => {
  try {
    const paymentTypeId = req.params.id;
    const { type } = req.body;

    const requiredFields = validateRequiredInput(req.body, ["name"]);

    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
        data: null,
      });
    }
    if (!paymentTypeId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field paymentTypeId is required`,
      });
    }
    if (!Object.values(PAYMENT_TYPES).includes(type)) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `Invalid payment type. Allowed types are: ${Object.values(
          PAYMENT_TYPES
        ).join(", ")}`,
        data: null,
      });
    }
    const response = await PaymentTypeService.updatePaymentType(
      paymentTypeId,
      req.body
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
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const getDetailsPaymentType = async (req, res) => {
  try {
    const paymentTypeId = req.params.id;
    if (!paymentTypeId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field paymentTypeId is required`,
      });
    }
    const response = await PaymentTypeService.getDetailsPaymentType(
      paymentTypeId
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
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const deletePaymentType = async (req, res) => {
  try {
    const paymentTypeId = req.params.id;
    if (!paymentTypeId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field paymentTypeId is required`,
      });
    }
    const response = await PaymentTypeService.deletePaymentType(paymentTypeId);
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

const deleteMany = async (req, res) => {
  try {
    const ids = req.body.paymentTypeIds;
    if (!ids || !ids.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field paymentTypeIds is required`,
      });
    }
    const response = await PaymentTypeService.deleteManyPaymentType(ids);
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

const getAllPaymentType = async (req, res) => {
  try {
    const params = req.query;
    const response = await PaymentTypeService.getAllPaymentType(params);
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
  createPaymentType,
  updatePaymentType,
  getDetailsPaymentType,
  deletePaymentType,
  getAllPaymentType,
  deleteMany,
};

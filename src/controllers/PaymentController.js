const { CONFIG_MESSAGE_ERRORS, PAYMENT_TYPES } = require("../configs");
const { validateRequiredInput } = require("../utils");
const PaymentTypeService = require("../services/PaymentService");

const createUrlPaymentVNPay = async (req, res) => {
  try {
    const requiredFields = validateRequiredInput(req.body, [
      "totalPrice",
      "language",
      "orderId",
    ]);

    let ipAddr =
      req.headers["x-forwarded-for"] ||
      req.connection.remoteAddress ||
      req.socket.remoteAddress ||
      req.connection.socket.remoteAddress;

    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
        data: null,
      });
    }
    const response = await PaymentTypeService.createUrlPaymentVNPay(
      req.body,
      ipAddr
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

const getVNPayIpnPaymentVNPay = async (req, res) => {
  try {
    let vnp_Params = req.query;

    const requiredFields = validateRequiredInput(vnp_Params, [
      "vnp_SecureHash",
      "vnp_TxnRef",
      "vnp_ResponseCode",
      "orderId"
    ]);

    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
        data: null,
      });
    }
    const response = await PaymentTypeService.getVNPayIpnPaymentVNPay(
      vnp_Params
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

module.exports = {
  createUrlPaymentVNPay,
  getVNPayIpnPaymentVNPay
};

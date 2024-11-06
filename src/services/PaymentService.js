const moment = require("moment/moment");
const {
  CONFIG_MESSAGE_ERRORS,
  CONTEXT_NOTIFICATION,
  ACTION_NOTIFICATION_ORDER,
} = require("../configs");
const dotenv = require("dotenv");
dotenv.config();
const Order = require("../models/OrderProduct");
const {
  getUserAndAdminTokens,
  pushNotification,
} = require("./NotificationService");

function sortObject(obj) {
  let sorted = {};
  let str = [];
  let key;
  for (key in obj) {
    if (obj.hasOwnProperty(key)) {
      str.push(encodeURIComponent(key));
    }
  }
  str.sort();
  for (key = 0; key < str.length; key++) {
    sorted[str[key]] = encodeURIComponent(obj[str[key]]).replace(/%20/g, "+");
  }
  return sorted;
}

const createUrlPaymentVNPay = (data, ipAddr) => {
  return new Promise(async (resolve, reject) => {
    const { totalPrice, language, orderId } = data;
    try {
      let date = new Date();
      let createDate = moment(date).format("YYYYMMDDHHmmss");

      let returnUrl = process.env.VNPAY_RETURN_URL_SUCCESS;
      let tmnCode = process.env.VNPAY_TMN_CODE;
      let secretKey = process.env.VNPAY_SECRET_KEY;
      let vnpUrl = process.env.VNPAY_RETURN_URL;
      let bankCode = data.bankCode || "NCB";

      let locale = language;
      if (locale === null || locale === "") {
        locale = "vn";
      }
      let codeOrder = moment(date).format("DDHHmmss");

      let currCode = "VND";
      let vnp_Params = {};
      vnp_Params["vnp_Version"] = "2.1.0";
      vnp_Params["vnp_Command"] = "pay";
      vnp_Params["vnp_TmnCode"] = tmnCode;
      vnp_Params["vnp_Locale"] = locale;
      vnp_Params["vnp_CurrCode"] = currCode;
      vnp_Params["vnp_TxnRef"] = orderId;
      vnp_Params["vnp_OrderInfo"] = "Thanh toan cho ma GD:" + codeOrder;
      vnp_Params["vnp_OrderType"] = "other";
      vnp_Params["vnp_Amount"] = totalPrice * 100;
      vnp_Params["vnp_ReturnUrl"] = returnUrl;
      vnp_Params["vnp_IpAddr"] = ipAddr;
      vnp_Params["vnp_CreateDate"] = createDate;
      if (bankCode !== null && bankCode !== "") {
        vnp_Params["vnp_BankCode"] = bankCode;
      }

      vnp_Params = sortObject(vnp_Params);

      let querystring = require("qs");
      let signData = querystring.stringify(vnp_Params, { encode: false });
      let crypto = require("crypto");
      let hmac = crypto.createHmac("sha512", secretKey);
      let signed = hmac.update(new Buffer(signData, "utf-8")).digest("hex");
      vnp_Params["vnp_SecureHash"] = signed;
      vnpUrl += "?" + querystring.stringify(vnp_Params, { encode: false });

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Created url success",
        typeError: "",
        data: vnpUrl,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getVNPayIpnPaymentVNPay = (data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const { orderId, ...rest } = data;
      let vnp_Params = JSON.parse(JSON.stringify(rest));
      let secureHash = vnp_Params["vnp_SecureHash"];

      delete vnp_Params["vnp_SecureHash"];
      delete vnp_Params["vnp_SecureHashType"];

      vnp_Params = sortObject(vnp_Params);
      let secretKey = process.env.VNPAY_SECRET_KEY;

      let querystring = require("qs");
      let signData = querystring.stringify(vnp_Params, { encode: false });
      let crypto = require("crypto");
      let hmac = crypto.createHmac("sha512", secretKey);
      let signed = hmac.update(new Buffer(signData, "utf-8")).digest("hex");

      if (secureHash === signed) {
        let orderId = vnp_Params["vnp_TxnRef"];
        let rspCode = vnp_Params["vnp_ResponseCode"];
        const existingOrder = await Order.findById(orderId);

        if (!existingOrder) {
          reject({
            status: CONFIG_MESSAGE_ERRORS.INVALID.status,
            message: `Order with ID ${orderId} not found`,
            typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
        const currentTime = moment();

        const formattedCurrentTime = currentTime.format(
          "YYYY-MM-DDTHH:mm:ss.SSSZ"
        );
        if (existingOrder) {
          existingOrder.isPaid = 1;
          existingOrder.paidAt = formattedCurrentTime;
          existingOrder.status = 1;
          await existingOrder.save();
          const { recipientIds, deviceTokens } = await getUserAndAdminTokens(
            existingOrder.user.toString()
          );

          await pushNotification({
            context: CONTEXT_NOTIFICATION.PAYMENT_VN_PAY,
            title: ACTION_NOTIFICATION_ORDER.PAYMENT_VN_PAY_SUCCESS,
            body: `Đơn hàng với id ${existingOrder?._id?.toString()} đã được thanh toán thành công`,
            referenceId: existingOrder._id?.toString(),
            recipientIds,
            deviceTokens,
          });
        }

        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Payment success",
          typeError: "",
          data: { RspCode: "00", totalPrice: existingOrder.totalPrice },
          statusMessage: "Success",
        });
      } else {
        const { recipientIds, deviceTokens } = await getUserAndAdminTokens(
          existingOrder.user.toString()
        );

        await pushNotification({
          context: CONTEXT_NOTIFICATION.PAYMENT_VN_PAY,
          title: ACTION_NOTIFICATION_ORDER.PAYMENT_VN_PAY_ERROR,
          body: `Đơn hàng với id ${existingOrder?._id?.toString()} đã toán thành công`,
          referenceId: existingOrder._id?.toString(),
          recipientIds,
          deviceTokens,
        });
        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Payment failed",
          typeError: "",
          data: { RspCode: "97" },
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  createUrlPaymentVNPay,
  getVNPayIpnPaymentVNPay,
};

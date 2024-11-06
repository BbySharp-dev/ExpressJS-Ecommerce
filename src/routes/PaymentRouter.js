const express = require("express");
const router = express.Router();
const dotenv = require("dotenv");
const PaymentController = require("../controllers/PaymentController");
dotenv.config();


router.post("/vnpay/create_payment_url", PaymentController.createUrlPaymentVNPay);
router.get("/vnpay/vnpay_ipn", PaymentController.getVNPayIpnPaymentVNPay);

module.exports = router;

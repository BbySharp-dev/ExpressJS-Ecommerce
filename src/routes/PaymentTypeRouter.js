const express = require("express");
const router = express.Router();
const { CONFIG_PERMISSIONS } = require("../configs");
const { AuthPermission } = require("../middleware/AuthPermission");
const PaymentTypeController = require("../controllers/PaymentTypeController");

router.post(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.PAYMENT_TYPE.CREATE),
  PaymentTypeController.createPaymentType
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.PAYMENT_TYPE.UPDATE),
  PaymentTypeController.updatePaymentType
);

router.get("/:id", PaymentTypeController.getDetailsPaymentType);


router.get("/", PaymentTypeController.getAllPaymentType);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.PAYMENT_TYPE.DELETE),
  PaymentTypeController.deleteMany
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.PAYMENT_TYPE.DELETE),
  PaymentTypeController.deletePaymentType
);

module.exports = router;

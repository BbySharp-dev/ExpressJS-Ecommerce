const express = require("express");
const router = express.Router();
const OrderController = require("../controllers/OrderController");
const { AuthPermission } = require("../middleware/AuthPermission");
const { CONFIG_PERMISSIONS } = require("../configs");

router.post(
  "/status/:orderId",
  AuthPermission("", true),
  OrderController.updateStatusOrder
);

router.post(
  "/",
  AuthPermission("", true),
  OrderController.createOrder
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.ORDER.UPDATE),
  OrderController.updateOrder
);

router.get(
  "/me",
  AuthPermission("", true),
  OrderController.getAllOrderOfMe
);

router.get(
  "/:orderId",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.ORDER.VIEW),
  OrderController.getDetailsOrder
);

router.get(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.ORDER.VIEW),
  OrderController.getAllOrder
);


router.post(
  "/cancel/:orderId",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.ORDER.UPDATE),
  OrderController.cancelOrderProduct
);

router.delete(
  "/:orderId",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.ORDER.DELETE),
  OrderController.deleteOrderProduct
);

// me

router.post(
  "/me/cancel/:orderId",
  AuthPermission("", true),
  OrderController.cancelOrderOfMe
);

router.get(
  "/me/:orderId",
  AuthPermission("", true),
  OrderController.getDetailsOrderOfMe
);



module.exports = router;

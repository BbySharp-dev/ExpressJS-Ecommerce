const express = require("express");
const router = express.Router();
const { CONFIG_PERMISSIONS } = require("../configs");
const { AuthPermission } = require("../middleware/AuthPermission");
const DeliveryTypeController = require("../controllers/DeliveryTypeController");

router.post(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.DELIVERY_TYPE.CREATE),
  DeliveryTypeController.createDeliveryType
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.DELIVERY_TYPE.UPDATE),
  DeliveryTypeController.updateDeliveryType
);

router.get("/:id", DeliveryTypeController.getDetailsDeliveryType);

router.get("/", DeliveryTypeController.getAllDeliveryType);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.DELIVERY_TYPE.DELETE),
  DeliveryTypeController.deleteMany
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SETTING.DELIVERY_TYPE.DELETE),
  DeliveryTypeController.deleteDeliveryType
);

module.exports = router;

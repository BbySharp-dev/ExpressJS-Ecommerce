const express = require("express");
const router = express.Router();
const { CONFIG_PERMISSIONS } = require("../configs");
const { AuthPermission } = require("../middleware/AuthPermission");
const NotificationController = require("../controllers/NotificationController");

router.get(
  "/",
  AuthPermission("", true),
  NotificationController.getListNotifications
);



router.post(
  "/all/read",
  AuthPermission("", true),
  NotificationController.readAllNotification
);

router.post(
  "/:id/read",
  AuthPermission("", true),
  NotificationController.readOneNotification
);

router.delete(
  "/:id",
  AuthPermission("", true),
  NotificationController.deleteNotification
);




module.exports = router;

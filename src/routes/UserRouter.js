const express = require("express");
const router = express.Router();
const UserController = require("../controllers/UserController");
const { CONFIG_PERMISSIONS } = require("../configs");
const { AuthPermission } = require("../middleware/AuthPermission");

router.post(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.USER.CREATE),
  UserController.createUser
);

router.get(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.USER.VIEW),
  UserController.getAllUser
);

router.get(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.USER.VIEW),
  UserController.getDetailsUser
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.USER.UPDATE),
  UserController.updateUser
);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.USER.DELETE),
  UserController.deleteMany
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.USER.DELETE),
  UserController.deleteUser
);

module.exports = router;

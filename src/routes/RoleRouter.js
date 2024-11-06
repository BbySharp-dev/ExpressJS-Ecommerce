const express = require("express");
const router = express.Router();
const roleController = require("../controllers/RoleController");
const { CONFIG_PERMISSIONS } = require("../configs");
const { AuthPermission } = require("../middleware/AuthPermission");

router.post(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.ROLE.CREATE),
  roleController.createRole
);

router.get(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.ROLE.VIEW),
  roleController.getAllRole
);

router.get(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.ROLE.VIEW),
  roleController.getDetailsRole
);

router.put(
  "/:id",
  // AuthPermission(CONFIG_PERMISSIONS.SYSTEM.ROLE.UPDATE),
  roleController.updateRole
);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.ROLE.DELETE),
  roleController.deleteManyRole
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.SYSTEM.ROLE.DELETE),
  roleController.deleteRole
);

module.exports = router;

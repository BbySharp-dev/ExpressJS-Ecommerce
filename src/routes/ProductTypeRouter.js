const express = require("express");
const router = express.Router();
const ProductTypeController = require("../controllers/ProductTypeController");
const { AuthPermission } = require("../middleware/AuthPermission");
const { CONFIG_PERMISSIONS } = require("../configs");

router.post(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT_TYPE.CREATE),
  ProductTypeController.createProductType
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT_TYPE.UPDATE),
  ProductTypeController.updateProductType
);

router.get(
  "/:id",
  ProductTypeController.getDetailsProductType
);

router.get(
  "/",
  ProductTypeController.getAllProductType
);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT_TYPE.DELETE),
  ProductTypeController.deleteManyProductType
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT_TYPE.DELETE),
  ProductTypeController.deleteProductType
);

module.exports = router;

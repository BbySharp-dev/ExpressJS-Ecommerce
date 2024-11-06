const express = require("express");
const router = express.Router();
const ProductController = require("../controllers/ProductController");
const { AuthPermission } = require("../middleware/AuthPermission");
const { CONFIG_PERMISSIONS } = require("../configs");

router.post(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT.CREATE),
  ProductController.createProduct
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT.UPDATE),
  ProductController.updateProduct
);

router.get(
  "/liked/me",
  AuthPermission("", true),
  ProductController.getAllProductLiked
);

router.get(
  "/viewed/me",
  AuthPermission("", true),
  ProductController.getAllProductViewed
);

router.get("/related", ProductController.getListRelatedProductBySlug);

router.get(
  "/public/slug/:slug",
  AuthPermission("", true, true),
  ProductController.getDetailsProductPublicBySlug
);

router.get(
  "/public/:id",
  AuthPermission("", true, true),
  ProductController.getDetailsProductPublic
);

router.get("/public", ProductController.getAllProductPublic);

router.get(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT.VIEW),
  ProductController.getDetailsProduct
);

router.get(
  "/",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT.VIEW),
  ProductController.getAllProduct
);

router.post("/like", AuthPermission("", true), ProductController.likeProduct);

router.post(
  "/unlike",
  AuthPermission("", true),
  ProductController.unlikeProduct
);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT.DELETE),
  ProductController.deleteMany
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.PRODUCT.DELETE),
  ProductController.deleteProduct
);

module.exports = router;

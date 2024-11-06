const express = require("express");
const router = express.Router();
const ReviewController = require("../controllers/ReviewController");
const { AuthPermission } = require("../middleware/AuthPermission");
const { CONFIG_PERMISSIONS } = require("../configs");

router.post("/", ReviewController.createReview);

router.put(
  "/me/:id",
  AuthPermission("", true),
  ReviewController.updateReviewMine
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.REVIEW.UPDATE),
  ReviewController.updateReview
);

router.get("/:id", ReviewController.getDetailsReview);



router.get("/", ReviewController.getAllReview);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.REVIEW.DELETE),
  ReviewController.deleteMany
);

router.delete(
  "/me/:id",
  AuthPermission("", true),
  ReviewController.deleteReviewMine
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_ORDER.REVIEW.DELETE),
  ReviewController.deleteReview
);

module.exports = router;

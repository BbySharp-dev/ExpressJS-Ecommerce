const express = require("express");
const router = express.Router();
const CommentController = require("../controllers/CommentController");
const { AuthPermission } = require("../middleware/AuthPermission");
const { CONFIG_PERMISSIONS } = require("../configs");

router.post("/reply", CommentController.replyComment);

router.post("/", CommentController.createComment);

router.put(
  "/me/:id",
  AuthPermission("", true),
  CommentController.updateMyComment
);

router.put(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.COMMENT.UPDATE),
  CommentController.updateComment
);

router.get("/public", CommentController.getAllCommentPublic);

router.get("/:id", CommentController.getDetailsComment);

router.get("/", CommentController.getAllComment);

router.delete(
  "/delete-many",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.COMMENT.DELETE),
  CommentController.deleteMany
);

router.delete(
  "/me/:id",
  AuthPermission("", true),
  CommentController.deleteMyComment
);

router.delete(
  "/:id",
  AuthPermission(CONFIG_PERMISSIONS.MANAGE_PRODUCT.COMMENT.DELETE),
  CommentController.deleteComment
);

module.exports = router;

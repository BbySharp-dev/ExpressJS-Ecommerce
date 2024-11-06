const express = require("express");
const router = express.Router();
const { CONFIG_PERMISSIONS } = require("../configs");
const { AuthPermission } = require("../middleware/AuthPermission");
const ReportController = require("../controllers/ReportController")

router.get(
  "/product-type/count",
  AuthPermission(CONFIG_PERMISSIONS.DASHBOARD),
  ReportController.getReportCountProductType
);

router.get(
  "/user-type/count",
  AuthPermission(CONFIG_PERMISSIONS.DASHBOARD),
  ReportController.getReportCountUser
);

router.get(
  "/all-records/count",
  AuthPermission(CONFIG_PERMISSIONS.DASHBOARD),
  ReportController.getReportCountRecords
);

router.get(
  "/revenue-total",
  AuthPermission(CONFIG_PERMISSIONS.DASHBOARD),
  ReportController.getReportTotalRevenue
);

router.get(
  "/order-status/count",
  AuthPermission(CONFIG_PERMISSIONS.DASHBOARD),
  ReportController.getReportCountOrderStatus
);

router.get(
  "/product-status/count",
  AuthPermission(CONFIG_PERMISSIONS.DASHBOARD),
  ReportController.getReportCountProductStatus
);

module.exports = router;

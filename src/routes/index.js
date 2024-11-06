const UserRouter = require("./UserRouter");
const AuthRouter = require("./AuthRouter");
const ProductRouter = require("./ProductRouter");
const OrderRouter = require("./OrderRouter");
const PaymentRouter = require("./PaymentRouter");
const ProductTypeRouter = require("./ProductTypeRouter");
const ReviewRouter = require("./ReviewRouter");
const RoleRouter = require("./RoleRouter");
const CityRouter = require("./CityRouter");
const DeliveryTypeRouter = require("./DeliveryTypeRouter");
const PaymentTypeRouter = require("./PaymentTypeRouter");
const ReportRouter = require("./ReportRouter");
const NotificationRouter = require("./NotificationRouter");
const CommentRouter = require("./CommentRouter");

const routes = (app) => {
  app.use("/api/auth", AuthRouter);
  app.use("/api/users", UserRouter);
  app.use("/api/products", ProductRouter);
  app.use("/api/product-types", ProductTypeRouter);
  app.use("/api/orders", OrderRouter);
  app.use("/api/payment", PaymentRouter);
  app.use("/api/reviews", ReviewRouter);
  app.use("/api/roles", RoleRouter);
  app.use("/api/city", CityRouter);
  app.use("/api/delivery-type", DeliveryTypeRouter);
  app.use("/api/payment-type", PaymentTypeRouter);
  app.use("/api/report", ReportRouter);
  app.use("/api/notifications", NotificationRouter);
  app.use("/api/comments", CommentRouter);
};

module.exports = routes;

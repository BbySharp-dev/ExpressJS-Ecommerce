const {
  CONFIG_MESSAGE_ERRORS,
  CONFIG_PERMISSIONS,
  ACTION_NOTIFICATION_ORDER,
} = require("../configs");
const Notification = require("../models/Notification");
const User = require("../models/UserModel");
const Role = require("../models/RoleModel");
const { uniqueValuesArr } = require("../utils");
const { getMessaging } = require("firebase-admin/messaging");

const pushMessageToFirebase = async (data) => {
  const { deviceTokens, title, body } = data;
  const message = {
    notification: {
      title,
      body,
    },
    tokens: deviceTokens,
  };

  await getMessaging().sendMulticast(message);
};

const getUserAndAdminTokens = async (userId) => {
  try {
    const currentUser = await User.findById(userId);
    const adminRoles = await Role.find({
      permissions: CONFIG_PERMISSIONS.ADMIN,
    });
    const adminRoleIds = adminRoles.map((role) => role._id);
    const adminUsers = await User.find({ role: { $in: adminRoleIds } });
    const adminDeviceTokens = [];
    const adminIds = [];
    adminUsers.forEach((admin) => {
      adminDeviceTokens?.push?.apply(adminDeviceTokens, admin.deviceTokens);
      adminIds.push(admin._id?.toString());
    });
    const uniqueIdUser = uniqueValuesArr([currentUser?._id?.toString(),...adminIds]);
    const uniqueDeviceToken = uniqueValuesArr([...currentUser?.deviceTokens,...adminDeviceTokens]);

    return { recipientIds: uniqueIdUser, deviceTokens: uniqueDeviceToken };
  } catch (error) {
    return { recipientIds: [], deviceTokens: [] };
  }
};

const pushNotification = (newNotification) => {
  return new Promise(async (resolve, reject) => {
    try {
      const { context, title, body, referenceId, recipientIds, deviceTokens } =
        newNotification;

      const notificationCreate = {
        context,
        title,
        body,
        referenceId,
        recipientIds: recipientIds.map((userId) => ({ userId, isRead: false })),
        isRead: false,
      };

      const createdNotification = await Notification.create(notificationCreate);
      if (deviceTokens.length > 0) {
        const mapTitle = {
          [ACTION_NOTIFICATION_ORDER.CANCEL_ORDER]: "Hủy đơn hàng",
          [ACTION_NOTIFICATION_ORDER.CREATE_ORDER]: "Đặt đơn hàng",
          [ACTION_NOTIFICATION_ORDER.WAIT_PAYMENT]: "Đơn hàng chờ thanh toán",
          [ACTION_NOTIFICATION_ORDER.WAIT_DELIVERY]: "Đơn hàng chờ giao hàng",
          [ACTION_NOTIFICATION_ORDER.DONE_ORDER]: "Hoàn thành đơn hàng",
          [ACTION_NOTIFICATION_ORDER.IS_DELIVERED]: "Đơn hàng đã được giao",
          [ACTION_NOTIFICATION_ORDER.IS_PAID]: "Đơn hàng đã được thanh toán",
          [ACTION_NOTIFICATION_ORDER.PAYMENT_VN_PAY_ERROR]:
            "Thanh toán vnpay thất bại",
          [ACTION_NOTIFICATION_ORDER.PAYMENT_VN_PAY_SUCCESS]:
            "Thanh toán vnpay thành công",
        };
        await pushMessageToFirebase({
          deviceTokens,
          title: mapTitle[title] || title,
          body,
        });
      }

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Created notification Success",
        typeError: "",
        statusMessage: "Success",
        data: createdNotification,
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getListNotifications = (userId, params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const page = params?.page ? +params.page : 1;
      const order = params?.order ?? "createdAt desc";
      const isRead = params?.isRead ?? "";
      const search = params?.search;

      const query = {};
      let sortOptions = {};

      if (order) {
        const orderFields = order
          .split(",")
          .map((field) => field.trim().split(" "));
        orderFields.forEach(([name, direction]) => {
          sortOptions[name] = direction.toLowerCase() === "asc" ? 1 : -1;
        });
      }
      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ title: searchRegex }];
      }

      if (isRead !== "") {
        query["recipientIds"] = {
          $elemMatch: { userId: userId, isRead: isRead },
        };
      } else {
        query["recipientIds.userId"] = userId;
      }

      const fieldsToSelect = {
        context: 1,
        title: 1,
        body: 1,
        _id: 1,
        referenceId: 1,
        createdAt: 1,
        "recipientIds.isRead": 1,
      };

      const totalCount = await Notification.countDocuments(query);
      const totalNew = await Notification.countDocuments({
        recipientIds: {
          $elemMatch: { userId: userId, isRead: false },
        },
      });

      const totalPage = Math.ceil(totalCount / limit);

      const startIndex = (page - 1) * limit;

      if (page === -1 && limit === -1) {
        const allNotification = await Notification.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect)
          .lean();

        const modifiedNotifications = allNotification.map((notification) => {
          const findIsRead = notification?.recipientIds?.find((item) => item?.userId?.toString() === userId)
          const { recipientIds, ...rest } = notification;
          return {
            ...rest,
            isRead: findIsRead?.isRead,
          };
        });

        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            notifications: modifiedNotifications,
            totalPage: 1,
            totalCount: totalCount,
            totalNew,
          },
        });
        return;
      }

      const allNotification = await Notification.find(query)
        .sort({ createdAt: -1 })
        .skip(startIndex)
        .limit(limit)
        .populate({
          path: "recipientIds.userId",
          select: "_id avatar",
        })
        .select(fieldsToSelect)
        .lean();

      const modifiedNotifications = allNotification.map((notification) => {
        const { recipientIds, ...rest } = notification;
        return {
          ...rest,
          isRead: notification.recipientIds[0].isRead,
        };
      });

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: {
          notifications: modifiedNotifications,
          totalPage: totalPage,
          totalCount: totalCount,
          totalNew,
        },
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const readOneNotification = (userId, notificationId, permissions) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkNotification = await Notification.findById(notificationId);

      if (!checkNotification) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The notification is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      const isUserInRecipients = checkNotification?.recipientIds?.some(
        (recipient) => recipient?.userId?.toString() === userId?.toString()
      );
      if (
        !isUserInRecipients &&
        !permissions.includes(CONFIG_PERMISSIONS.ADMIN)
      ) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "You can't permission",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      checkNotification?.recipientIds?.forEach((recipient) => {
        if (recipient?.userId?.toString() === userId?.toString()) {
          recipient.isRead = true;
        }
      });
      await checkNotification.save();

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "The notification are marked as read",
        typeError: "",
        data: checkNotification,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const readAllNotification = (userId) => {
  return new Promise(async (resolve, reject) => {
    try {
      const notifications = await Notification.find({
        "recipientIds.userId": userId,
        "recipientIds.isRead": false,
      });

      const updatePromises = notifications.map(async (notification) => {
        notification.recipientIds.forEach((recipient) => {
          if (
            recipient.userId.toString() === userId.toString() &&
            !recipient.isRead
          ) {
            recipient.isRead = true;
          }
        });
        return notification.save();
      });

      // Chờ cho tất cả các promise cập nhật hoàn thành
      await Promise.all(updatePromises);

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "All notifications are marked as read",
        typeError: "",
        data: [],
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteNotification = (userId, notificationId, permissions) => {
  return new Promise(async (resolve, reject) => {
    try {
      const notification = await Notification.findById(notificationId);

      if (!notification) {
        return {
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The notification does not exist",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        };
      }
      const isUserInRecipients = notification?.recipientIds?.some(
        (recipient) => recipient?.userId?.toString() === userId?.toString()
      );
      if (
        !isUserInRecipients &&
        !permissions.includes(CONFIG_PERMISSIONS.ADMIN)
      ) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "You can't permission",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      const updatedRecipientIds = notification?.recipientIds?.filter(
        (recipient) => recipient?.userId?.toString() !== userId?.toString()
      );

      if (updatedRecipientIds.length === 0) {
        await Notification.findByIdAndDelete(notificationId);
      } else {
        notification.recipientIds = updatedRecipientIds;
        await notification.save();
      }

      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Notification deleted successfully",
        typeError: "",
        data: notification,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  pushNotification,
  getListNotifications,
  readOneNotification,
  deleteNotification,
  readAllNotification,
  getUserAndAdminTokens,
};

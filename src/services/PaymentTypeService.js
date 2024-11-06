const { CONFIG_MESSAGE_ERRORS } = require("../configs");
const PaymentType = require("../models/PaymentType");

const createPaymentType = (paymentType) => {
  return new Promise(async (resolve, reject) => {
    const { name, type } = paymentType;
    try {
      const checkPayment = await PaymentType.findOne({
        $or: [{ name: name }, { type: type }],
      });
      if (checkPayment !== null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
          message: "The name or type of payment type is existed",
          typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
          data: null,
          statusMessage: "Error",
        });
      }
      const createdPayment = await PaymentType.create({
        name,
        type
      });
      if (createdPayment) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Created payment type success",
          typeError: "",
          data: createdPayment,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updatePaymentType = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkPayment = await PaymentType.findOne({
        _id: id,
      });

      if (!checkPayment) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The payment type name is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      if (data.name && data.name !== checkPayment.name) {
        const existedName = await PaymentType.findOne({
          name: data.name,
          _id: { $ne: id },
        });

        if (existedName !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The payment type name is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }

      if (data.type && data.type !== checkPayment.type) {
        const existedType = await PaymentType.findOne({
          type: data.type,
          _id: { $ne: id },
        });

        if (existedType !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The payment type type is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }

      const updatedPayment = await PaymentType.findByIdAndUpdate(id, data, {
        new: true,
      });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated payment type success",
        typeError: "",
        data: updatedPayment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deletePaymentType = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkPayment = await PaymentType.findOne({
        _id: id,
      });
      if (checkPayment === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The payment type is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await PaymentType.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted payment type success",
        typeError: "",
        data: checkPayment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyPaymentType = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await PaymentType.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete payment types success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsPaymentType = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkPayment = await PaymentType.findOne({
        _id: id,
      });
      if (checkPayment === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The payment type is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkPayment,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllPaymentType = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ? +params.page : 1;
      const order = params?.order ?? "createdAt desc";
      const query = {};
      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }

      const totalCount = await PaymentType.countDocuments(query);

      const totalPage = Math.ceil(totalCount / limit);

      const startIndex = (page - 1) * limit;

      let sortOptions = {};
      if (order) {
        const orderFields = order
          .split(",")
          .map((field) => field.trim().split(" "));
        orderFields.forEach(([name, direction]) => {
          sortOptions[name] = direction.toLowerCase() === "asc" ? 1 : -1;
        });
      }

      const fieldsToSelect = {
        name: 1,
        createdAt: 1,
        type: 1,
      };

      if (page === -1 && limit === -1) {
        const allPaymentType = await PaymentType.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect);
        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            paymentTypes: allPaymentType,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const allPaymentType = await PaymentType.find(query)
        .skip(startIndex)
        .limit(limit)
        .sort(sortOptions)
        .select(fieldsToSelect);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          paymentTypes: allPaymentType,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  createPaymentType,
  updatePaymentType,
  getDetailsPaymentType,
  deletePaymentType,
  getAllPaymentType,
  deleteManyPaymentType,
};

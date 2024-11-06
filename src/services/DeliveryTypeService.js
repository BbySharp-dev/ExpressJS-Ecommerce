const { CONFIG_MESSAGE_ERRORS } = require("../configs");
const DeliveryType = require("../models/DeliveryType");

const createDeliveryType = (newType) => {
  return new Promise(async (resolve, reject) => {
    const { name,price } = newType;
    try {
      const checkDelivery = await DeliveryType.findOne({
        name: name,
      });
      if (checkDelivery !== null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
          message: "The name of delivery type is existed",
          typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
          data: null,
          statusMessage: "Error",
        });
      }
      const createdDeliveryType = await DeliveryType.create({
        name,
        price
      });
      if (createdDeliveryType) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Created delivery type success",
          typeError: "",
          data: createdDeliveryType,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updateDeliveryType = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkDelivery = await DeliveryType.findOne({
        _id: id,
      });
      if (!checkDelivery) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The type of delivery is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      if (data.name && data.name !== checkDelivery.name) {
        const existedName = await DeliveryType.findOne({
          name: data.name,
          _id: { $ne: id },
        });

        if (existedName !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The name of delivery type is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }

      const updatedDelivery = await DeliveryType.findByIdAndUpdate(id, data, {
        new: true,
      });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated delivery type success",
        typeError: "",
        data: updatedDelivery,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteDeliveryType = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkDelivery = await DeliveryType.findOne({
        _id: id,
      });
      if (checkDelivery === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The delivery type is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await DeliveryType.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted delivery type success",
        typeError: "",
        data: checkDelivery,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyDeliveryType = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await DeliveryType.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete delivery type success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsDeliveryType = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkDelivery = await DeliveryType.findOne({
        _id: id,
      });
      if (checkDelivery === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The delivery type is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkDelivery,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllDeliveryType = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ?  +params.page :  1;
      const order = params?.order ?? "createdAt desc";
      const query = {};
      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex }];
      }

      const totalCount = await DeliveryType.countDocuments(query);

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
        price: 1,
      };

      if (page === -1 && limit === -1) {
        const allDelivery = await DeliveryType.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect);
        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            deliveryTypes: allDelivery,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }

      const allDelivery = await DeliveryType.find(query)
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
          deliveryTypes: allDelivery,
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
  createDeliveryType,
  updateDeliveryType,
  getDetailsDeliveryType,
  deleteDeliveryType,
  getAllDeliveryType,
  deleteManyDeliveryType,
};

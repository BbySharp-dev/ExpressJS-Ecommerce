const { CONFIG_MESSAGE_ERRORS } = require("../configs");
const ProductType = require("../models/ProductType");

const createProductType = (newProductType) => {
  return new Promise(async (resolve, reject) => {
    const { slug, name } = newProductType;
    try {
      const checkProductType = await ProductType.findOne({
        slug: slug,
      });
      if (checkProductType !== null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
          message: "The product type slug is existed",
          typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
          data: null,
          statusMessage: "Error",
        });
      }
      const newProductType = await ProductType.create({
        name,
        slug,
      });
      if (newProductType) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Created product type success",
          typeError: "",
          data: newProductType,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updateProductType = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkProductType = await ProductType.findOne({
        _id: id,
      });

      if (!checkProductType) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The name of type product is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      if (data.name && data.name !== checkProductType.name) {
        const existedName = await ProductType.findOne({
          name: data.name,
          _id: { $ne: id },
        });

        if (existedName !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The name of type product is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }

      const updatedProductType = await ProductType.findByIdAndUpdate(id, data, {
        new: true,
      });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated product type success",
        typeError: "",
        data: updatedProductType,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteProductType = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkProductType = await ProductType.findOne({
        _id: id,
      });
      if (checkProductType === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product type is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await ProductType.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted product type success",
        typeError: "",
        data: checkProductType,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyProductType = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await ProductType.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete product types success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsProductType = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkProductType = await ProductType.findOne({
        _id: id,
      });
      if (checkProductType === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The product type is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: checkProductType,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllProductType = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ?  +params.page :  1;
      const order = params?.order ?? "createdAt desc";
      const query = {};
      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [{ name: searchRegex },{ slug: searchRegex }];
      }

      const totalCount = await ProductType.countDocuments(query);

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
        slug: 1,
      };

      if (page === -1 && limit === -1) {
        const allProductType = await ProductType.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect);
        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            productTypes: allProductType,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }
      
      const allProductType = await ProductType.find(query)
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
          productTypes: allProductType,
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
  createProductType,
  updateProductType,
  getDetailsProductType,
  deleteProductType,
  getAllProductType,
  deleteManyProductType,
};

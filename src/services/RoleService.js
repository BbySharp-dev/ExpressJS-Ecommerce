const Role = require("../models/RoleModel");
const { CONFIG_MESSAGE_ERRORS, CONFIG_PERMISSIONS } = require("../configs");

const createRole = (newRole) => {
  return new Promise(async (resolve, reject) => {
    const { name, permissions } = newRole;
    try {
      const existedRole = await Role.findOne({
        name: name,
      });
      if (existedRole !== null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
          message: "The name of role is existed",
          typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      const createRole = await Role.create({
        name,
        permissions: permissions?.includes(CONFIG_PERMISSIONS.ADMIN) ? [] : permissions
      });
      if (createRole) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Created role success",
          typeError: "",
          data: createRole,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updateRole = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkRole = await Role.findOne({
        _id: id,
      });
      if (!checkRole) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The role is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      if (
        checkRole.permissions.includes(CONFIG_PERMISSIONS.ADMIN) ||
        checkRole.permissions.includes(CONFIG_PERMISSIONS.BASIC) ||
        checkRole.name === "Admin" ||
        checkRole.name === "Basic"
      ) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          statusMessage: "Error",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          message: `You can't update permission with admin or basic role`,
          data: null,
        });
        return;
      }

      if (data.name && data.name !== checkRole.name) {
        const existedName = await Role.findOne({
          name: data.name,
          _id: { $ne: id },
        });

        if (existedName !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The name of role is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }

      const updatedRole = await Role.findByIdAndUpdate(id, data, { new: true });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated role success",
        typeError: "",
        data: updatedRole,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteRole = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkRole = await Role.findOne({
        _id: id,
      });
      if (checkRole === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The role is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await Role.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted role success",
        typeError: "",
        data: checkRole,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyRole = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await Role.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete roles success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllRole = (params) => {
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

      const totalCount = await Role.countDocuments(query);

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
        permissions: 1,
      };


      if (page === -1 && limit === -1) {
        const allRole = await Role.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect);

        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            roles: allRole,
            totalPage: 1,
            totalCount: totalCount,
          },
        });
        return;
      }
      const allRole = await Role.find(query)
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
          roles: allRole,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsRole = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const role = await Role.findOne({
        _id: id,
      });
      if (role === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The role is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: role,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  createRole,
  updateRole,
  deleteRole,
  getAllRole,
  getDetailsRole,
  deleteManyRole,
};

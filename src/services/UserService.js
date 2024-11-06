const User = require("../models/UserModel");
const bcrypt = require("bcrypt");
const { CONFIG_MESSAGE_ERRORS, CONFIG_USER_TYPE } = require("../configs");
const { isAdminPermission } = require("../utils");
const mongoose = require("mongoose");

const createUser = (newUser) => {
  return new Promise(async (resolve, reject) => {
    const {
      email,
      password,
      phoneNumber,
      address,
      city,
      role,
      firstName,
      lastName,
      middleName,
      avatar,
    } = newUser;
    try {
      const existedUser = await User.findOne({
        email: email,
      });
      if (existedUser !== null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
          message: "The email of user is existed",
          typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
          data: null,
          statusMessage: "Error",
        });
      }
      const hash = bcrypt.hashSync(password, 10);
      const userCreate = {
        email,
        password: hash,
        phoneNumber: phoneNumber,
        address,
        firstName,
        lastName,
        middleName,
        avatar,
        status: 1,
      };
      if (city) {
        userCreate.city = city;
      }
      if (role) {
        userCreate.role = role;
      }
      const createdUser = await User.create(userCreate);
      if (createdUser) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
          message: "Created user success",
          typeError: "",
          data: createdUser,
          statusMessage: "Success",
        });
      }
    } catch (e) {
      reject(e);
    }
  });
};

const updateUser = (id, data) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkUser = await User.findOne({
        _id: id,
      });
      if (!checkUser) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The user is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }

      if (data.email && data.email !== checkUser.email) {
        const existedName = await User.findOne({
          email: data.email,
          _id: { $ne: id },
        });

        if (existedName !== null) {
          resolve({
            status: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.status,
            message: "The email of user is existed",
            typeError: CONFIG_MESSAGE_ERRORS.ALREADY_EXIST.type,
            data: null,
            statusMessage: "Error",
          });
          return;
        }
      }

      if (
        isAdminPermission(checkUser.permissions) &&
        (data.status !== checkUser.status || data.email !== checkUser.email)
      ) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.status,
          message: "You can't change admin's email or status",
          typeError: CONFIG_MESSAGE_ERRORS.UNAUTHORIZED.type,
          data: null,
          statusMessage: "Error",
        });
      }
      const dataUser = {
        email: data.email,
        password: checkUser.password,
        phoneNumber: data.phoneNumber,
        address: data.address,
        firstName: data.firstName,
        lastName: data.lastName,
        middleName: data.middleName,
        city: checkUser.city,
        role: checkUser.role,
        middleName: data.middleName,
        avatar: data.avatar,
        status: data.status,
      };
      if (data.city) {
        dataUser.city = data.city;
      }
      if (data.role) {
        dataUser.role = data.role;
      }
      const updatedUser = await User.findByIdAndUpdate(id, dataUser, {
        new: true,
      });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Updated user success",
        typeError: "",
        data: updatedUser,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteUser = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const checkUser = await User.findOne({
        _id: id,
      }).select("-password");
      if (checkUser === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The user is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
      }

      await User.findByIdAndDelete(id);
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Deleted user success",
        typeError: "",
        data: checkUser,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const deleteManyUser = (ids) => {
  return new Promise(async (resolve, reject) => {
    try {
      await User.deleteMany({ _id: ids });
      resolve({
        status: CONFIG_MESSAGE_ERRORS.ACTION_SUCCESS.status,
        message: "Delete users success",
        typeError: "",
        data: null,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getAllUser = (params) => {
  return new Promise(async (resolve, reject) => {
    try {
      const limit = params?.limit ? +params?.limit : 10;
      const search = params?.search ?? "";
      const page = params?.page ?  +params.page :  1;
      const order = params?.order ?? "createdAt desc";
      const query = {};
      const roleId = params?.roleId ?? "";
      const status = params?.status ?? "";
      const cityId = params?.cityId ?? "";
      const userType = params?.userType ?? "";

      if (search) {
        const searchRegex = { $regex: search, $options: "i" };

        query.$or = [
          { email: searchRegex },
          { firstName: searchRegex },
          { lastName: searchRegex },
          { middleName: searchRegex },
        ];
      }

      if (roleId) {
        const roleIds = roleId
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.role =
          roleIds.length > 1
            ? { $in: roleIds }
            : mongoose.Types.ObjectId(roleId);
      }
      if (cityId) {
        const cityIds = cityId
          ?.split("|")
          .map((id) => mongoose.Types.ObjectId(id));
        query.city =
          cityIds.length > 1
            ? { $in: cityIds }
            : mongoose.Types.ObjectId(cityId);
      }

      if (status) {
        const statusId = status?.split("|").map((id) => id);
        query.status = { $in: statusId };
      }

      if (userType) {
        const userTypeIds = userType?.split("|").map((id) => id);
        query.userType = { $in: userTypeIds };
      }

      const totalCount = await User.countDocuments(query);

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
        status: 1,
        email: 1,
        role: 1,
        createdAt: 1,
        firstName: 1,
        lastName: 1,
        middleName: 1,
        city: 1,
        phoneNumber: 1,
        userType: 1
      };

      if (page === -1 && limit === -1) {
        const allUser = await User.find(query)
          .sort(sortOptions)
          .select(fieldsToSelect)
          .populate({
            path: "role",
            select: "name permissions",
          })
          .lean();

        resolve({
          status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
          message: "Success",
          typeError: "",
          statusMessage: "Success",
          data: {
            users: allUser,
            totalPage: 1,
            totalCount: totalCount,
          },
        });

        return;
      }

      const allUser = await User.find(query)
        .skip(startIndex)
        .limit(limit)
        .sort(sortOptions)
        .select(fieldsToSelect)
        .populate([
          {
            path: "role",
            select: "name permissions",
          },
          {
            path: "city",
            select: "name",
          },
        ])
        .lean();

      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        statusMessage: "Success",
        data: {
          users: allUser,
          totalPage: totalPage,
          totalCount: totalCount,
        },
      });
    } catch (e) {
      reject(e);
    }
  });
};

const getDetailsUser = (id) => {
  return new Promise(async (resolve, reject) => {
    try {
      const user = await User.findOne({
        _id: id,
      })
        .select("-password")
        .populate({
          path: "role",
          select: "name permissions",
        })
        .lean();

      if (user === null) {
        resolve({
          status: CONFIG_MESSAGE_ERRORS.INVALID.status,
          message: "The user is not existed",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          data: null,
          statusMessage: "Error",
        });
        return;
      }
      resolve({
        status: CONFIG_MESSAGE_ERRORS.GET_SUCCESS.status,
        message: "Success",
        typeError: "",
        data: user,
        statusMessage: "Success",
      });
    } catch (e) {
      reject(e);
    }
  });
};

module.exports = {
  createUser,
  updateUser,
  deleteUser,
  getAllUser,
  getDetailsUser,
  deleteManyUser,
};

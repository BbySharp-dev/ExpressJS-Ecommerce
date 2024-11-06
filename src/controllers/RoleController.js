const RoleService = require("../services/RoleService");
const {
  validateRequiredInput,
  getAllPermissionValues,
  existedPermissionRole,
} = require("../utils");
const { CONFIG_MESSAGE_ERRORS, CONFIG_PERMISSIONS } = require("../configs");

const createRole = async (req, res) => {
  try {
    const requiredFields = validateRequiredInput(req.body, ["name"]);
    if (requiredFields?.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field ${requiredFields.join(", ")} is required`,
      });
    }
    const response = await RoleService.createRole(req.body);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const updateRole = async (req, res) => {
  try {
    const roleId = req.params.id;
    const dataBody = req.body;
    if (!roleId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field roleId is required`,
        data: null,
      });
    } else if (dataBody.permissions && dataBody.permissions.length > 0) {
      if (!existedPermissionRole(dataBody.permissions)) {
        return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
          status: "Error",
          typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
          message: `The ${dataBody.permissions?.join(
            ", "
          )} is not contained system`,
          data: null,
        });
      }
    }
    const response = await RoleService.updateRole(roleId, req.body);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const deleteRole = async (req, res) => {
  try {
    const roleId = req.params.id;
    if (!roleId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field roleId is required`,
      });
    }
    const response = await RoleService.deleteRole(roleId);
    const { data, status, typeError, message } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const deleteManyRole = async (req, res) => {
  try {
    const ids = req.body.roleIds;
    if (!ids || !ids.length) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field roleIds is required`,
      });
    }
    const response = await RoleService.deleteManyRole(ids);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const getAllRole = async (req, res) => {
  try {
    const params = req.query;
    const response = await RoleService.getAllRole(params);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

const getDetailsRole = async (req, res) => {
  try {
    const roleId = req.params.id;
    if (!roleId) {
      return res.status(CONFIG_MESSAGE_ERRORS.INVALID.status).json({
        status: "Error",
        typeError: CONFIG_MESSAGE_ERRORS.INVALID.type,
        message: `The field roleId is required`,
      });
    }
    const response = await RoleService.getDetailsRole(roleId);
    const { data, status, typeError, message, statusMessage } = response;
    return res.status(status).json({
      typeError,
      data,
      message,
      status: statusMessage,
    });
  } catch (e) {
    return res.status(CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.status).json({
      message: "Internal Server Error",
      data: null,
      status: "Error",
      typeError: CONFIG_MESSAGE_ERRORS.INTERNAL_ERROR.type,
    });
  }
};

module.exports = {
  createRole,
  updateRole,
  deleteRole,
  getAllRole,
  getDetailsRole,
  deleteManyRole,
};
